from flask import Flask, render_template, request, abort, url_for, redirect
import requests
import base64
import logging
import random
from dotenv import load_dotenv
import os
from functools import wraps
from apscheduler.schedulers.background import BackgroundScheduler
import time
from threading import Lock, Thread
import unicodedata
import re

app = Flask(__name__)

# Função para normalizar textos removendo acentos e caracteres especiais
def normalize_text(text):
    # Normaliza para decomposição Unicode (NFD)
    text = unicodedata.normalize('NFD', text)
    # Remove os diacríticos
    text = ''.join(c for c in text if not unicodedata.combining(c))
    # Deixa em minúsculas e remove caracteres não alfanuméricos (exceto espaços)
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', '', text)
    return text

# Path para armazenar a contagem de acessos
ACCESS_FILE = 'access_count.txt'

def get_access_count():
    if os.path.exists(ACCESS_FILE):
        with open(ACCESS_FILE, 'r') as file:
            return int(file.read())
    return 0

def increment_access_count():
    count = get_access_count() + 1
    with open(ACCESS_FILE, 'w') as file:
        file.write(str(count))

@app.route('/acessos')
def acessos():
    increment_access_count()
    count = get_access_count()
    return render_template('acessos.html', numero_de_acessos=count)

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
        self.scheduler = BackgroundScheduler()
        self._setup_token_refresh_scheduler()
        if not self.access_token:
            raise EnvironmentError("ACCESS_TOKEN não encontrado. Execute o fluxo de autorização.")
        self.PRODUTOS_POR_PAGINA_API = 100
        self.MAX_PAGES = 50  # Limita o número máximo de páginas para evitar loops infinitos
        self.last_token_refresh_time = time.time()  # Armazena o momento da última atualização

    def _setup_token_refresh_scheduler(self):
        self.scheduler.add_job(
            func=self._refresh_access_token,
            trigger='interval',
            seconds=7200  # Atualiza a cada 2 horas
        )
        self.scheduler.start()

    def _refresh_access_token(self):
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
            self.last_token_refresh_time = time.time()  # Atualiza o horário do refresh
            logger.info("Tokens atualizados com sucesso")
            
            # Atualiza as variáveis de ambiente e o arquivo .env (não recomendado para produção)
            os.environ['ACCESS_TOKEN'] = self.access_token
            os.environ['REFRESH_TOKEN'] = self.refresh_token
            with open('.env', 'w') as env_file:
                env_file.write(f"BLING_CLIENT_ID={os.getenv('BLING_CLIENT_ID')}\n")
                env_file.write(f"BLING_CLIENT_SECRET={os.getenv('BLING_CLIENT_SECRET')}\n")
                env_file.write(f"ACCESS_TOKEN={self.access_token}\n")
                env_file.write(f"REFRESH_TOKEN={self.refresh_token}\n")
            
        except Exception as e:
            logger.error(f"Falha ao atualizar tokens: {str(e)}")

    def check_and_refresh_token(self):
        # Assume que o token tem validade de 7200 segundos (2 horas)
        # Realiza refresh 100 segundos antes da expiração
        if time.time() - self.last_token_refresh_time > 7100:
            logger.info("Token expirado pelo tempo, atualizando...")
            self._refresh_access_token()

    def get_all_products(self):
        # Verifica se o token precisa ser atualizado antes de iniciar as requisições
        self.check_and_refresh_token()

        all_products = []
        page = 1
        
        while page <= self.MAX_PAGES:
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
                    continue  # Tenta novamente após atualizar o token
                
                response.raise_for_status()
                
                data = response.json()
                products = data.get('data', [])
                
                if not products:
                    break
       
                all_products.extend(products)
                
                # Se a quantidade de produtos retornados for menor que o limite, chegamos ao fim.
                if len(products) < self.PRODUTOS_POR_PAGINA_API:
                    break
                
                page += 1
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Falha na requisição da API: {str(e)}")
                break

        return all_products

# Inicializa a API Bling
bling_api = BlingAPI()

# Cache de produtos
cached_products = []
cache_timestamp = 0
CACHE_DURATION = 600  # 10 minutos em segundos
cache_lock = Lock()

def update_product_cache():
    global cached_products, cache_timestamp
    try:
        products = bling_api.get_all_products()
        with cache_lock:
            cached_products = products
            cache_timestamp = time.time()
        logger.info("Cache de produtos atualizado com sucesso.")
    except Exception as e:
        logger.error(f"Erro ao atualizar o cache de produtos: {str(e)}")

def get_cached_products():
    global cached_products, cache_timestamp
    with cache_lock:
        is_expired = (time.time() - cache_timestamp > CACHE_DURATION)
        current_cache = cached_products.copy()
    if current_cache and is_expired:
        logger.info("Cache expirado. Atualizando cache em background...")
        Thread(target=update_product_cache).start()
        return current_cache
    elif not current_cache:
        logger.info("Cache vazio. Atualizando cache de forma síncrona...")
        update_product_cache()
        with cache_lock:
            return cached_products
    return current_cache

# Agendador para atualizar o cache de produtos a cada 10 minutos
product_scheduler = BackgroundScheduler()
product_scheduler.add_job(update_product_cache, 'interval', seconds=CACHE_DURATION)
product_scheduler.start()

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return "Erro: código de autorização não encontrado."
    
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

        with open('.env', 'a') as env_file:
            env_file.write(f'ACCESS_TOKEN={access_token}\n')
            env_file.write(f'REFRESH_TOKEN={refresh_token}\n')

        os.environ['ACCESS_TOKEN'] = access_token
        os.environ['REFRESH_TOKEN'] = refresh_token

        return "Tokens obtidos e armazenados com sucesso!"
    else:
        return f"Erro ao obter tokens: {response.text}"

@app.template_filter('brl')
def format_brl(value):
    try:
        return f'R$ {float(value):,.2f}'.replace(',', 'v').replace('.', ',').replace('v', '.')
    except (ValueError, TypeError):
        return 'R$ 0,00'

def handle_api_errors(f):
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
    # Recebe a query de busca e normaliza o texto
    search_query = request.args.get('search', '').strip()
    normalized_search = normalize_text(search_query) if search_query else ''

    palavras = ["viol", "cord", "p10", "xlr", "pandeiro", 
                "teclado", "pedestal", "bat", "cap", "tarr", "guit", "baix",
                "p2", "afin", "som", "baq", "mic", "pilha", "radio", "porta", "pen", "amp",
                "instr", "amp", "uku", "cav", "corre", "ded", "fone", "pele", "mesa", "palhe", "mini", "amp"]

    produtos = get_cached_products()

    # Filtra os produtos verificando se alguma das palavras chave está presente
    produtos_filtrados = [
        produto for produto in produtos
        if any(palavra in normalize_text(produto.get('nome', '')) for palavra in palavras)
    ]

    # Ordena inicialmente por nome (normalizado)
    produtos_ordenados = sorted(produtos_filtrados, key=lambda p: normalize_text(p.get('nome', '')))

    message = None
    if normalized_search:
        # Separa a busca em tokens
        query_tokens = normalized_search.split()
        # Filtra produtos que contenham pelo menos um dos tokens
        produtos_filtrados = [
            produto for produto in produtos_ordenados
            if any(token in normalize_text(produto.get('nome', '')) for token in query_tokens)
        ]

        if not produtos_filtrados:
            message = f"Nenhum produto encontrado para '{search_query}'."
        else:
            # Função de pontuação: maior pontuação para produtos que possuem mais tokens e 
            # com menor índice (mais próximos do início) para o primeiro token encontrado.
            def product_score(prod):
                normalized_name = normalize_text(prod.get('nome', ''))
                score = sum(1 for token in query_tokens if token in normalized_name)
                positions = [normalized_name.find(token) for token in query_tokens if token in normalized_name]
                min_pos = min(positions) if positions else float('inf')
                return (score, -min_pos)
            # Ordena os produtos com base na pontuação (decrescente)
            produtos_filtrados = sorted(produtos_filtrados, key=product_score, reverse=True)
        produtos_ordenados = produtos_filtrados
    else:
        random.shuffle(produtos_ordenados)

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
        message=message,
    )

@app.route('/produto/<codigo>')
@handle_api_errors
def product_detail(codigo):
    produtos = get_cached_products()
    produto = next((p for p in produtos if p.get('codigo') == codigo), None)
    
    if not produto:
        abort(404, description="Produto não encontrado")
        
    return render_template('produto.html', produto=produto)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
