from flask import Flask, render_template, request
import requests
import base64
from dotenv import load_dotenv
import os
app = Flask(__name__)

# Carregar variáveis do arquivo .env
load_dotenv()

# Acessando as variáveis do ambiente
ACCESS_TOKEN = os.getenv("ACCESS_TOKEN")
REFRESH_TOKEN = os.getenv("REFRESH_TOKEN")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

# Endpoints
PRODUTOS_URL = "https://api.bling.com.br/Api/v3/produtos"
TOKEN_URL = "https://api.bling.com.br/Api/v3/oauth/token"

def get_produtos(access_token):
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }
    response = requests.get(PRODUTOS_URL, headers=headers)
    if response.status_code == 200:
        dados = response.json()
        if 'data' in dados:
            return dados['data']
        else:
            print("Estrutura de resposta inesperada:", dados)
            return []
    else:
        print("Erro ao obter produtos:", response.status_code, response.text)
        return []

def refresh_access_token(client_id, client_secret, refresh_token):
    credenciais = f"{client_id}:{client_secret}"
    encoded_credentials = base64.b64encode(credenciais.encode("utf-8")).decode("utf-8")
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "Authorization": f"Basic {encoded_credentials}"
    }
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }
    response = requests.post(TOKEN_URL, headers=headers, data=data)
    if response.status_code == 200:
        tokens = response.json()
        novo_access_token = tokens.get("access_token")
        novo_refresh_token = tokens.get("refresh_token")
        return novo_access_token, novo_refresh_token
    else:
        print("Erro ao atualizar token:", response.status_code, response.text)
        return None, None

@app.route('/', methods=['GET'])
def index():
    global ACCESS_TOKEN, REFRESH_TOKEN
    produtos = get_produtos(ACCESS_TOKEN)
    
    if not produtos:
        novo_access, novo_refresh = refresh_access_token(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN)
        if novo_access:
            ACCESS_TOKEN = novo_access
            REFRESH_TOKEN = novo_refresh
            produtos = get_produtos(ACCESS_TOKEN)
        else:
            produtos = []
    
    produtos_ordenados = sorted(produtos, key=lambda p: p["nome"].lower() if "nome" in p else "")
    search_query = request.args.get('search', '').strip().lower()
    
    if search_query:
        palavras_busca = search_query.split()
        def calcular_relevancia(produto):
            nome_produto = produto["nome"].lower()
            posicoes = [nome_produto.find(palavra) for palavra in palavras_busca]
            if all(pos >= 0 for pos in posicoes) and all(pos1 < pos2 for pos1, pos2 in zip(posicoes, posicoes[1:])):
                return sum(posicoes)
            return float('inf')
        
        produtos_ordenados = sorted(produtos_ordenados, key=calcular_relevancia)

    return render_template("catalogo.html", produtos=produtos_ordenados)

@app.template_filter('formatarPreco')
def formatar_preco(valor):
    if valor:
        return f"R$ {valor:,.2f}".replace(',', 'X').replace('.', ',').replace('X', '.')
    return 'R$ 0,00'


# Nova rota para exibir os detalhes de um produto
@app.route('/produto/<codigo>', methods=['GET'])
def produto(codigo):
    global ACCESS_TOKEN
    produtos = get_produtos(ACCESS_TOKEN)
    
    # Encontrar o produto pelo código
    produto = next((p for p in produtos if p["codigo"] == codigo), None)
    
    if not produto:
        return "Produto não encontrado", 404
    
    return render_template("produto.html", produto=produto)


if __name__ == "__main__":
    app.run(debug=True)
