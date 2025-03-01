import os
import requests
import time
from dotenv import load_dotenv

load_dotenv()

class HomologacaoBling:
    def __init__(self):
        self.base_url = "https://api.bling.com.br/Api/v3/homologacao"
        self.client_id = os.getenv("BLING_CLIENT_ID")
        self.client_secret = os.getenv("BLING_CLIENT_SECRET")
        self.access_token = os.getenv("ACCESS_TOKEN")
        self.refresh_token = os.getenv("REFRESH_TOKEN")
        self.current_hash = None
        self.start_time = None
        self.product_id = None

    def _refresh_token(self):
        try:
            response = requests.post(
                "https://api.bling.com.br/Api/v3/oauth/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": self.refresh_token
                },
                auth=(self.client_id, self.client_secret)
            )
            response.raise_for_status()
            token_data = response.json()
            self.access_token = token_data["access_token"]
            self.refresh_token = token_data["refresh_token"]
            return True
        except Exception as e:
            print(f"Erro ao renovar token: {str(e)}")
            return False

    def _make_request(self, method, endpoint, data=None):
        if time.time() - self.start_time > 10:
            raise TimeoutError("Tempo total excedeu 10 segundos")

        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        if self.current_hash:
            headers["x-bling-homologacao"] = self.current_hash

        try:
            response = requests.request(
                method=method,
                url=f"{self.base_url}{endpoint}",
                headers=headers,
                json=data
            )

            if response.status_code == 401:
                if self._refresh_token():
                    return self._make_request(method, endpoint, data)
                else:
                    raise Exception("Falha na autenticação")

            response.raise_for_status()
            self.current_hash = response.headers.get("x-bling-homologacao")
            return response.json()

        except requests.exceptions.RequestException as e:
            print(f"Erro na requisição {method} {endpoint}: {str(e)}")
            if e.response:
                print("Detalhes:", e.response.text)
            raise

    def executar_fluxo_homologacao(self):
        self.start_time = time.time()
        
        try:
            # Passo 1: GET
            print("\n🔹 Passo 1/5: Obtendo dados do produto...")
            get_data = self._make_request("GET", "/produtos")
            produto = get_data["data"]
            print("Dados obtidos:", produto)
            time.sleep(2)

            # Passo 2: POST
            print("\n🔹 Passo 2/5: Criando novo produto...")
            post_data = {"nome": produto["nome"], "preco": produto["preco"], "codigo": produto["codigo"]}
            post_response = self._make_request("POST", "/produtos", post_data)
            self.product_id = post_response["data"]["id"]
            print(f"Produto criado ID: {self.product_id}")
            time.sleep(2)

            # Passo 3: PUT
            print("\n🔹 Passo 3/5: Atualizando produto...")
            put_data = {**post_data, "nome": "Copo"}
            self._make_request("PUT", f"/produtos/{self.product_id}", put_data)
            print("Produto atualizado com sucesso")
            time.sleep(2)

            # Passo 4: PATCH
            print("\n🔹 Passo 4/5: Alterando situação...")
            patch_data = {"situacao": "I"}
            self._make_request("PATCH", f"/produtos/{self.product_id}/situacoes", patch_data)
            print("Situação atualizada para Inativo")
            time.sleep(2)

            # Passo 5: DELETE
            print("\n🔹 Passo 5/5: Removendo produto...")
            self._make_request("DELETE", f"/produtos/{self.product_id}")
            print("Produto removido com sucesso")

            tempo_total = time.time() - self.start_time
            print(f"\n✅ Homologação concluída em {tempo_total:.2f} segundos")

        except Exception as e:
            print(f"\n❌ Falha no processo: {str(e)}")
            if self.product_id:
                print("Executando limpeza...")
                try:
                    self._make_request("DELETE", f"/produtos/{self.product_id}")
                except:
                    pass
            raise

# Configuração do ambiente
if __name__ == "__main__":
    bling = HomologacaoBling()
    
    try:
        bling.executar_fluxo_homologacao()
    except TimeoutError as te:
        print(f"\n❌ {str(te)} - Reinicie o processo")
    except Exception as e:
        print(f"\n❌ Erro crítico: {str(e)} - Verifique suas credenciais e conexão")