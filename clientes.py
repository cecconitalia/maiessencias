import requests
from flask import Flask, render_template, request

app = Flask(__name__)

# URL base da API (substitua pela URL correta)
BASE_URL = 'https://sua-api.com'

# Função para obter os clientes
def get_all_clients():
    try:
        response = requests.get(f'{BASE_URL}/clientes')  # Substitua a URL de acordo com a API
        response.raise_for_status()  # Verifica se a resposta foi bem-sucedida
        return response.json()  # Retorna os dados em formato JSON
    except requests.exceptions.RequestException as e:
        print(f'Erro ao obter clientes: {e}')
        return []

@app.route('/clientes')
def clientes():
    pagina = request.args.get('pagina', 1, type=int)
    
    # Obtém todos os clientes
    clientes = get_all_clients()
    
    # Paginação (exibindo 5 clientes por página)
    clientes_por_pagina_ui = 5
    total_clientes = len(clientes)
    total_paginas = (total_clientes + clientes_por_pagina_ui - 1) // clientes_por_pagina_ui

    inicio = (pagina - 1) * clientes_por_pagina_ui
    fim = inicio + clientes_por_pagina_ui
    clientes_pagina = clientes[inicio:fim]

    return render_template(
        'clientes.html',  # Nome do arquivo HTML
        clientes=clientes_pagina,
        pagina=pagina,
        total_paginas=total_paginas
    )

if __name__ == '__main__':
    app.run(debug=True)
