from flask import Flask, render_template, request, abort, url_for, redirect
import requests
import base64
import logging
import random
import json
from dotenv import load_dotenv
import os
from functools import wraps
from apscheduler.schedulers.background import BackgroundScheduler  # Agendador de tarefas

# Configuração do Flask
app = Flask(__name__)

# Carregar variáveis de ambiente
load_dotenv()
client_id = os.getenv('BLING_CLIENT_ID')
client_secret = os.getenv('BLING_CLIENT_SECRET')
required_env_vars = ['BLING_CLIENT_ID', 'BLING_CLIENT_SECRET', 'ACCESS_TOKEN', 'REFRESH_TOKEN']
missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    raise EnvironmentError(f"Variáveis de ambiente faltando: {', '.join(missing_vars)}")

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Classe para integrar com a API do Bling
class BlingAPI:
    def __init__(self):
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = os.getenv('REFRESH_TOKEN')
        self.access_token = os.getenv('ACCESS_TOKEN')
        self.base_url = "https://api.bling.com.br/Api/v3"
        self.session = requests.Session()
        self.scheduler = BackgroundScheduler()  # Agendador de tarefas
        self._setup_token_refresh_scheduler()   # Inicia o agendador

        if not self.access_token:
            raise EnvironmentError("ACCESS_TOKEN não encontrado. Execute o fluxo de autorização.")
        self.PRODUTOS_POR_PAGINA_API = 100

    # ... (outros métodos existentes)

    def get_product_by_code(self, codigo):
        """Busca um produto específico pelo código usando API v3"""
        endpoint = f"{self.base_url}/produtos"
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Accept': 'application/json'
        }
        
        params = {
            'codigo': codigo,
            'limite': 1  # Apenas 1 resultado necessário
        }
        
        try:
            response = self.session.get(endpoint, headers=headers, params=params)
            
            # Se o token expirar, atualiza e tenta novamente
            if response.status_code == 401:
                self._refresh_access_token()
                return self.get_product_by_code(codigo)  # Repetir após atualizar token
                
            response.raise_for_status()  # Lança exceção para erros HTTP
            
            data = response.json()
            if data['data']:
                return self._enrich_product_data(data['data'][0])  # Retorna o produto encontrado
                
            return None  # Retorna None se o produto não for encontrado
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Erro ao buscar produto {codigo}: {str(e)}")
            return None  # Retorna None em caso de erro

    def _enrich_product_data(self, produto):
            """Complementa dados do produto com informações adicionais da API"""
            # Buscar detalhes completos do produto
            endpoint = f"{self.base_url}/produtos/{produto['id']}"
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Accept': 'application/json'
            }
            
            try:
                response = self.session.get(endpoint, headers=headers)
                response.raise_for_status()  # Lança exceção para erros HTTP
                full_data = response.json()
                
                # Combinar dados básicos com detalhes completos
                return {**produto, **full_data}
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Erro ao buscar detalhes do produto {produto['id']}: {str(e)}")
                return produto  # Retorna os dados básicos em caso de erro

    def _setup_token_refresh_scheduler(self):
        """Inicia o agendador para atualizar tokens a cada 30 segundos."""
        self.scheduler.add_job(
            func=self._refresh_access_token,
            trigger='interval',
            seconds=7200  # Atualiza a cada 2 horas
        )
        self.scheduler.start()

    def _refresh_access_token(self):
        """Atualiza o token de acesso OAuth2"""
        try:
            auth_string = f"{self.client_id}:{self.client_secret}"
            encoded_auth = base64.b64encode(auth_string.encode()).decode()
            
            headers = {
                'Authorization': f'Basic {encoded_auth}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            data = {
                'grant_type': 'refresh_token',
                'refresh_token': self.refresh_token
            }
            
            response = self.session.post(
                f"{self.base_url}/oauth/token",
                headers=headers,
                data=data,
                timeout=10
            )
            response.raise_for_status()
            
            tokens = response.json()
            self.access_token = tokens['access_token']
            self.refresh_token = tokens['refresh_token']
            logger.info("Tokens atualizados com sucesso")
            
            # Atualiza o .env (não recomendado para produção)
            os.environ['ACCESS_TOKEN'] = self.access_token
            os.environ['REFRESH_TOKEN'] = self.refresh_token
            with open('.env', 'w') as env_file:
                env_file.write(f"BLING_CLIENT_ID={os.getenv('BLING_CLIENT_ID')}\n")
                env_file.write(f"BLING_CLIENT_SECRET={os.getenv('BLING_CLIENT_SECRET')}\n")
                env_file.write(f"ACCESS_TOKEN={self.access_token}\n")
                env_file.write(f"REFRESH_TOKEN={self.refresh_token}\n")
            
        except Exception as e:
            logger.error(f"Falha ao atualizar tokens: {str(e)}")

    def get_all_products(self):
        """Obtém todos os produtos da API, lidando com a limitação de 100 produtos por requisição."""
        all_products = []
        page = 1
        
        while True:
            try:
                headers = {
                    'Authorization': f'Bearer {self.access_token}',
                    'Accept': 'application/json'
                }
                
                params = {
                    'pagina': page,
                    'limite': self.PRODUTOS_POR_PAGINA_API
                }
                
                response = self.session.get(
                    f"{self.base_url}/produtos",
                    headers=headers,
                    params=params,
                    timeout=15
                )
                
                if response.status_code == 401:
                    logger.info("Token expirado, atualizando...")
                    self._refresh_access_token()
                    continue  # Repetir a requisição após atualizar o token
                
                response.raise_for_status()
                
                data = response.json()
                products = data.get('data', [])
                
                if not products:
                    break
       
       
                all_products.extend(products)
                
                # Se a quantidade de produtos retornados for menor que o limite, chegamos ao fim.
                if len(products) < self.PRODUTOS_POR_PAGINA_API:
                    break
                
                page += 1  # Avança para a próxima página
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Falha na requisição da API: {str(e)}")
                break

        return all_products

# Inicializa a API Bling
bling_api = BlingAPI()

@app.route('/callback')
def callback():
    """Callback de autorização, trocando o código por tokens"""
    code = request.args.get('code')
    if not code:
        return "Erro: código de autorização não encontrado."
    
    # Troca o código por token de acesso
    token_url = 'https://www.bling.com.br/Api/v3/oauth/token'
    credentials = f'{client_id}:{client_secret}'
    credentials_base64 = base64.b64encode(credentials.encode()).decode('utf-8')

    headers = {
        'Authorization': f'Basic {credentials_base64}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    data = {
        'grant_type': 'authorization_code',
        'code': code
    }

    response = requests.post(token_url, headers=headers, data=data)
    
    if response.status_code == 200:
        tokens = response.json()
        access_token = tokens.get('access_token')
        refresh_token = tokens.get('refresh_token')

        # Atualiza o .env com os tokens obtidos
        with open('.env', 'a') as env_file:
            env_file.write(f'ACCESS_TOKEN={access_token}\n')
            env_file.write(f'REFRESH_TOKEN={refresh_token}\n')

        # Atualiza as variáveis de ambiente também
        os.environ['ACCESS_TOKEN'] = access_token
        os.environ['REFRESH_TOKEN'] = refresh_token

        return "Tokens obtidos e armazenados com sucesso!"
    else:
        return f"Erro ao obter tokens: {response.text}"


@app.template_filter('brl')
def format_brl(value):
    """Formata valor para Real Brasileiro"""
    try:
        return f'R$ {float(value):,.2f}'.replace(',', 'v').replace('.', ',').replace('v', '.')
    except (ValueError, TypeError):
        return 'R$ 0,00'

def handle_api_errors(f):
    """Tratamento de erros da API"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except RuntimeError as e:
            logger.error(f"Erro na API: {str(e)}")
            return render_template('error.html', message="Serviço temporariamente indisponível"), 503
        except Exception as e:
            logger.error(f"Erro inesperado: {str(e)}")
            return render_template('error.html', message="Ocorreu um erro inesperado"), 500
    return wrapper

@app.route('/')
@handle_api_errors
def index():
        # Carregar as informações do arquivo JSON
    with open('informacoes_empresa.json', 'r') as f:
        informacoes = json.load(f)

    """Página principal do catálogo"""
    search_query = request.args.get('search', '').strip().lower()

    # Lista das palavras para filtrar
    palavras = ["essencia", "aromat", "sache", "oleo", "agua", "difus"]

    # Obtém todos os produtos (pode ser mais de 100)
    produtos = bling_api.get_all_products()

    # Filtra os produtos que contenham pelo menos uma das palavras
    produtos_filtrados = [
        produto for produto in produtos
        if any(palavra in produto.get('nome', '').lower() for palavra in palavras)
    ]

    # Ordena os produtos inicialmente por nome (ordem alfabética)
    produtos_ordenados = sorted(produtos_filtrados, key=lambda p: p.get('nome', '').lower())

    message = None
    if search_query:
        # Filtra os produtos que contêm o termo digitado
        produtos_filtrados = [
            produto for produto in produtos_ordenados
            if search_query in produto.get('nome', '').lower()
        ]
        if not produtos_filtrados:
            message = f"Nenhum produto encontrado para '{search_query}'."
        else:
            produtos_filtrados = sorted(
                produtos_filtrados,
                key=lambda p: p.get('estoque', {}).get('saldoVirtualTotal', 0),
                reverse=True
            )
            produtos_filtrados = sorted(
                produtos_filtrados,
                key=lambda p: p.get('nome', '').lower().find(search_query)
            )
        produtos_ordenados = produtos_filtrados
    else:
        # Embaralha os produtos apenas quando não há busca
        random.shuffle(produtos_ordenados)

    # Paginação para a interface (exibindo 30 produtos por página)
    produtos_por_pagina_ui = 30
    pagina = request.args.get('pagina', 1, type=int)
    total_produtos = len(produtos_ordenados)
    total_paginas = (total_produtos + produtos_por_pagina_ui - 1) // produtos_por_pagina_ui

    inicio = (pagina - 1) * produtos_por_pagina_ui
    fim = inicio + produtos_por_pagina_ui
    produtos_pagina = produtos_ordenados[inicio:fim]

    return render_template(
        'catalogo.html',
        produtos=produtos_pagina,
        pagina=pagina,
        total_paginas=total_paginas,
        message=message, informacoes=informacoes
    )


@app.route('/produto/<codigo>')
@handle_api_errors
def product_detail(codigo):
    url = 'https://api.bling.com.br/Api/v3/produtos'
    """Página de detalhes do produto com tratamento seguro de dados"""
    with open('informacoes_empresa.json', 'r') as f:
        informacoes = json.load(f)
    
    # Tenta buscar o produto pela API
    produto_raw = bling_api.get_product_by_code(codigo)
    
    # Log para verificar o retorno da API
    app.logger.info(f"Produto com código {codigo} retornado pela API: {produto_raw}")
    
    if not produto_raw:
        app.logger.error(f"Produto com código {codigo} não encontrado.")
        abort(404, description="Produto não encontrado")
    
    # Normalização dos dados, incluindo campos essenciais
    produto = {
        'id': produto_raw.get('id'),
        'codigo': produto_raw.get('codigo'),
        'nome': produto_raw.get('nome'),
        'preco': produto_raw.get('preco', 0),
        'descricaoCurta': produto_raw.get('descricaoCurta', ''),
        'descricaoComplementar': produto_raw.get('descricaoComplementar', ''),
        'observacoes': produto_raw.get('observacoes', ''),
        'imagemURL': produto_raw.get('imagemURL', ''),
        'unidade': produto_raw.get('unidade', 'UN'),
        'tipo': produto_raw.get('tipo', ''),
        'situacao': produto_raw.get('situacao', ''),
        'formato': produto_raw.get('formato', ''),
        'pesoLiquido': produto_raw.get('pesoLiquido', 0),
        'pesoBruto': produto_raw.get('pesoBruto', 0),
        'volumes': produto_raw.get('volumes', 0),
        'itensPorCaixa': produto_raw.get('itensPorCaixa', 0),
        'gtin': produto_raw.get('gtin', ''),
        'gtinEmbalagem': produto_raw.get('gtinEmbalagem', ''),
        'tipoProducao': produto_raw.get('tipoProducao', ''),
        'condicao': produto_raw.get('condicao', 0),
        'freteGratis': produto_raw.get('freteGratis', False),
        'marca': produto_raw.get('marca', ''),
        'linkExterno': produto_raw.get('linkExterno', ''),
        'descricaoEmbalagemDiscreta': produto_raw.get('descricaoEmbalagemDiscreta', ''),
        
        # Campos de categoria, estoque, fornecedor, tributacao, midia, dimensões, estrutura, etc.
        'categoria': produto_raw.get('categoria', {}),
        'estoque': produto_raw.get('estoque', {}),
        'fornecedor': produto_raw.get('fornecedor', {}),
        'dimensoes': produto_raw.get('dimensoes', {}),
        'tributacao': produto_raw.get('tributacao', {}),
        'midia': produto_raw.get('midia', {}),
        'linhaProduto': produto_raw.get('linhaProduto', {}),
        'estrutura': produto_raw.get('estrutura', {}),
        'camposCustomizados': produto_raw.get('camposCustomizados', []),
        'variacoes': produto_raw.get('variacoes', []),
    }

    # Processando informações de imagens
    produto['imagens'] = []

    # Verifica a presença de imagens externas e internas
    midia = produto.get('midia', {})
    if midia:
        externas = midia.get('imagens', {}).get('externas', [])
        internas = midia.get('imagens', {}).get('internas', [])
        imagens_extraidas = [img.get('link') for img in externas + internas if img.get('link')]
        produto['imagens'].extend(imagens_extraidas)
    
    # Adiciona a imagem principal (imagemURL), se ela não estiver na lista
    if produto.get('imagemURL') and produto['imagemURL'] not in produto['imagens']:
        produto['imagens'].insert(0, produto['imagemURL'])
    
    # Expande as informações de fornecedor
    fornecedor = produto['fornecedor']
    produto['fornecedor_nome'] = fornecedor.get('contato', {}).get('nome', 'Não informado')
    produto['fornecedor_codigo'] = fornecedor.get('codigo', 'Não informado')
    
    # Expande as informações de estoque
    estoque = produto['estoque']
    produto['estoque_total'] = estoque.get('saldoVirtualTotal', 0)
    
    # Expande as informações de tributação
    tributacao = produto['tributacao']
    produto['tributacao_ncm'] = tributacao.get('ncm', 'Não informado')
    produto['tributacao_cest'] = tributacao.get('cest', 'Não informado')
    
    # Expande as dimensões (caso exista)
    dimensoes = produto['dimensoes']
    produto['dimensoes_largura'] = dimensoes.get('largura', 0)
    produto['dimensoes_altura'] = dimensoes.get('altura', 0)
    produto['dimensoes_profundidade'] = dimensoes.get('profundidade', 0)
    produto['dimensoes_unidade'] = dimensoes.get('unidadeMedida', 'Não especificado')
    
    # Retorna a página HTML com todos os dados
    return render_template('produto.html', 
                           produto=produto,
                           informacoes=informacoes)
   
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
