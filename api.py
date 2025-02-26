import base64
import json
import requests
import webbrowser
import time

# Configuração da API Bling
client_id = "042a8ccfc73a3c6f10b44aa7ecf3bd352178d222"
secret_key = "d2f8a09f145b66b3931e6ebc87d474193e8b3631751fc1bbc6813af2725d"
auth_url = f"https://www.bling.com.br/b/Api/v3/oauth/authorize?response_type=code&client_id={client_id}&state=9cfdbc52f3746b057bcdd44148007718"
token_url = "https://www.bling.com.br/Api/v3/oauth/token"
token_file = "token.json"

def save_tokens(token_data):
    """Salva os tokens no arquivo JSON."""
    with open(token_file, "w") as f:
        json.dump(token_data, f)

def load_tokens():
    """Carrega os tokens do arquivo."""
    try:
        with open(token_file, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return None

def get_code():
    """Abre a URL de autenticação e pede para o usuário colar o código."""
    print("\n🔹 Abra o link abaixo e autorize o aplicativo no Bling:")
    print(auth_url)
    webbrowser.open(auth_url)  # Abre automaticamente no navegador
    time.sleep(2)  # Aguarda 2 segundos para garantir que a página seja aberta
    return input("\n🔑 Cole aqui o código de autorização obtido na URL: ").strip()

def get_token_from_code(auth_code):
    """Troca o código de autorização pelo token de acesso e refresh token."""
    credentials = base64.b64encode(f"{client_id}:{secret_key}".encode()).decode()

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {credentials}"
    }

    payload = {
        "grant_type": "authorization_code",
        "code": auth_code
    }

    response = requests.post(token_url, data=payload, headers=headers)
    if response.status_code == 200:
        token_data = response.json()
        save_tokens(token_data)
        print("✅ Token obtido e salvo com sucesso!")
        return token_data["access_token"]
    else:
        print("❌ Erro ao obter o token:", response.json())
        return None

def refresh_token():
    """Renova o token de acesso usando o refresh token."""
    tokens = load_tokens()
    if not tokens or "refresh_token" not in tokens:
        print("⚠️ Nenhum refresh token encontrado. Obtendo novo código de autorização...")
        auth_code = get_code()
        return get_token_from_code(auth_code)

    credentials = base64.b64encode(f"{client_id}:{secret_key}".encode()).decode()

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {credentials}"
    }

    payload = {
        "grant_type": "refresh_token",
        "refresh_token": tokens["refresh_token"]
    }

    response = requests.post(token_url, data=payload, headers=headers)
    if response.status_code == 200:
        new_tokens = response.json()
        save_tokens(new_tokens)
        print("✅ Token renovado com sucesso!")
        return new_tokens["access_token"]
    else:
        print("❌ Erro ao renovar o token. É necessário gerar um novo código.")
        auth_code = get_code()
        return get_token_from_code(auth_code)

def get_access_token():
    """Obtém um token válido, seja renovando ou solicitando um novo."""
    tokens = load_tokens()
    if tokens and "access_token" in tokens:
        return tokens["access_token"]

    # Se não houver token salvo, solicitar código manualmente
    auth_code = get_code()
    return get_token_from_code(auth_code)

# Obtém um token de acesso automaticamente
access_token = get_access_token()
print(f"\n🔑 Token de Acesso Atual: {access_token}")
