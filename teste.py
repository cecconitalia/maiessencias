import unittest
from unittest.mock import MagicMock, patch
from flask import Flask, session, template_rendered, request
from datetime import datetime
from freezegun import freeze_time

# Importe o seu aplicativo Flask e as funções que você deseja testar
from app import app, db, User, Pedido, ItemPedido, PrimeCode, Comissao, Slide, calcular_total_carrinho, calcular_frete, normalize_text, get_cached_products

class AppTestCase(unittest.TestCase):
    def setUp(self):
        """Configura o ambiente de teste."""
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # Use um banco de dados na memória para testes
        app.config['WTF_CSRF_ENABLED'] = False  # Desabilita o CSRF para testes
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()
        self.client = app.test_client()

        # Configurar um usuário de teste
        self.user = User(nome='Test User', email='test@example.com')
        self.user.set_senha('password')
        db.session.add(self.user)
        db.session.commit()

    def tearDown(self):
        """Limpa o ambiente de teste."""
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def login(self, email, senha):
        """Simula o login de um usuário."""
        return self.client.post('/login', data={'email': email, 'senha': senha})

    def logout(self):
        """Simula o logout de um usuário."""
        return self.client.get('/logout')

    def test_index_route(self):
        """Testa a rota principal '/'."""

        # Mock get_cached_products para retornar dados de teste
        mock_products = [
            {'id': 1, 'nome': 'Violão Clássico', 'preco': 100.00, 'estoque': {'saldoVirtualTotal': 10}},
            {'id': 2, 'nome': 'Guitarra Elétrica', 'preco': 300.00, 'estoque': {'saldoVirtualTotal': 5}},
        ]
        with patch('app.get_cached_products', return_value=mock_products):
            response = self.client.get('/')
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Viol\xc3\xa3o Cl\xc3\xa1ssico', response.data) # Corrigido para UTF-8
            self.assertIn(b'Guitarra El\xc3\xa9trica', response.data) # Corrigido para UTF-8

    def test_product_detail_route(self):
        """Testa a rota '/produto/<codigo>'."""

        # Mock get_cached_products para retornar um produto específico
        mock_products = [
            {'id': 1, 'codigo': 'VC001', 'nome': 'Violão Clássico', 'descricao': 'Ótimo para iniciantes', 'preco': 100.00, 'estoque': {'saldoVirtualTotal': 10}}
        ]
        with patch('app.get_cached_products', return_value=mock_products):
            response = self.client.get('/produto/VC001')
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Viol\xc3\xa3o Cl\xc3\xa1ssico', response.data) # Corrigido para UTF-8
            self.assertIn(b'timo para iniciantes', response.data) # Corrigido para UTF-8

    def test_adicionar_ao_carrinho_route(self):
        """Testa a rota '/adicionar-ao-carrinho'."""

        # Mock get_cached_products
        mock_products = [
            {'id': 1, 'nome': 'Bateria Acústica', 'preco': 500.00, 'codigo': 'BA001', 'estoque': {'saldoVirtualTotal': 2}}
        ]
        with patch('app.get_cached_products', return_value=mock_products):
            response = self.client.post('/adicionar-ao-carrinho', data={'produto_id': '1', 'quantidade': 1})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json, {
                'success': True,
                'message': 'Produto adicionado ao carrinho!',
                'cart_total_items': 1,
                'estoque_disponivel': 1
            })

            # Adicionar mais do que o estoque disponível
            response = self.client.post('/adicionar-ao-carrinho', data={'produto_id': '1', 'quantidade': 2})
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json, {
                'success': False,
                'message': 'Estoque insuficiente. Disponível: 1',
                'estoque_disponivel': 1
            })

    def test_ver_carrinho_route(self):
        """Testa a rota '/carrinho'."""

        # Simular um carrinho na sessão
        with self.client.session_transaction() as sess:
            sess['carrinho'] = {
                '1': {'id': 1, 'nome': 'Teclado Yamaha', 'preco': 200.00, 'quantidade': 2}
            }

        response = self.client.get('/carrinho')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Teclado Yamaha', response.data)
        self.assertIn(b'R$ 400,00', response.data)

    def test_remover_do_carrinho_route(self):
        """Testa a rota '/remover-do-carrinho/<produto_id>'."""

        # Simular um carrinho na sessão
        with self.client.session_transaction() as sess:
            sess['carrinho'] = {
                '1': {'id': 1, 'nome': 'Microfone Shure', 'preco': 150.00, 'quantidade': 1}
            }

        response = self.client.post('/remover-do-carrinho/1')
        self.assertEqual(response.status_code, 302)  # Redireciona para o carrinho
        self.assertEqual(response.location, '/carrinho')

        # Verificar se o carrinho está vazio após a remoção
        with self.client.session_transaction() as sess:
            self.assertEqual(sess['carrinho'], {})

    def test_login_logout_routes(self):
        """Testa as rotas de login e logout."""

        # Tentativa de login falha
        response = self.client.post('/login', data={'email': 'test@example.com', 'senha': 'wrong_password'})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Credenciais inv\xc3\xa1lidas', response.data)  # Corrigido para UTF-8

        # Login bem-sucedido
        response = self.login('test@example.com', 'password')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, '/')

        # Acesso a uma rota protegida
        response = self.client.get('/perfil')
        self.assertEqual(response.status_code, 200)

        # Logout
        response = self.logout()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, '/')

        # Acesso à rota protegida após o logout
        response = self.client.get('/perfil')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, '/login?next=%2Fperfil')

    def test_calcular_total_carrinho(self):
        """Testa a função calcular_total_carrinho."""
        carrinho = {
            '1': {'preco': 10.0, 'quantidade': 2},
            '2': {'preco': 20.0, 'quantidade': 1}
        }
        total = calcular_total_carrinho(carrinho)
        self.assertEqual(total, 40.0)

    def test_calcular_frete(self):
        """Testa a função calcular_frete."""
        frete_local = calcular_frete('89870-000', 50.00)
        self.assertEqual(frete_local['valor'], 29.90)
        self.assertEqual(frete_local['tipo'], 'local')

        frete_nacional = calcular_frete('12345-678', 200.00)
        self.assertEqual(frete_nacional['valor'], 49.90)
        self.assertEqual(frete_nacional['tipo'], 'nacional')

        frete_gratis_local = calcular_frete('89870-000', 150.00)
        self.assertEqual(frete_gratis_local['valor'], 0.0)

        frete_gratis_nacional = calcular_frete('12345-678', 600.00)
        self.assertEqual(frete_gratis_nacional['valor'], 0.0)

    def test_normalize_text(self):
        """Testa a função normalize_text."""
        self.assertEqual(normalize_text('AçÚçAr'), 'acucar')
        self.assertEqual(normalize_text('Olá, Mundo!'), 'ola mundo')
        self.assertEqual(normalize_text('Teste 123'), 'teste 123')

    def test_admin_dashboard_route(self):
        """Testa a rota '/admin'."""

        # Criar um usuário administrador
        admin_user = User(nome='Admin User', email='admin@example.com', is_admin=True)
        admin_user.set_senha('admin_password')
        db.session.add(admin_user)
        db.session.commit()

        # Tentar acessar sem login
        response = self.client.get('/admin')
        self.assertEqual(response.status_code, 302)  # Redireciona para login

        # Logar como administrador
        self.login('admin@example.com', 'admin_password')

        # Acessar o dashboard
        response = self.client.get('/admin')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Painel Administrativo', response.data)

        # Deslogar
        self.logout()

    def test_admin_usuarios_route(self):
        """Testa a rota '/admin/usuarios'."""

        # Criar mais usuários para testar a paginação
        for i in range(25):
            user = User(nome=f'User {i}', email=f'user{i}@example.com')
            user.set_senha('password')
            db.session.add(user)
        db.session.commit()

        # Logar como administrador
        self.login('admin@example.com', 'admin_password')

        # Acessar a página de usuários
        response = self.client.get('/admin/usuarios')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Gerenciamento de Usu\xc3\xa1rios', response.data)  # Corrigido para UTF-8

        # Deslogar
        self.logout()

    def test_admin_novo_usuario_route(self):
        """Testa a rota '/admin/usuario/novo'."""

        # Logar como administrador
        self.login('admin@example.com', 'admin_password')

        # Tentar criar um novo usuário
        response = self.client.post('/admin/usuario/novo', data={
            'nome': 'Novo Usuário',
            'email': 'novo@example.com',
            'senha': 'nova_senha'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Usu\xc3\xa1rio criado com sucesso!', response.data)  # Corrigido para UTF-8

        # Deslogar
        self.logout()

    def test_admin_usuario_detalhes_route(self):
        """Testa a rota '/admin/usuario/<int:user_id>'."""

        # Logar como administrador
        self.login('admin@example.com', 'admin_password')

        # Acessar os detalhes do usuário
        response = self.client.get(f'/admin/usuario/{self.user.id}')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Test User', response.data)

        # Tentar atualizar o usuário
        response = self.client.post(f'/admin/usuario/{self.user.id}', data={
            'nome': 'Usuário Atualizado',
            'email': 'atualizado@example.com',
            'ativo': 'true',
            'is_admin': 'false'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Usu\xc3\xa1rio atualizado com sucesso!', response.data)  # Corrigido para UTF-8

        # Deslogar
        self.logout()

    def test_admin_excluir_usuario_route(self):
        """Testa a rota '/admin/usuario/<int:user_id>/excluir'."""

        # Logar como administrador
        self.login('admin@example.com', 'admin_password')

        # Tentar excluir o usuário
        response = self.client.post(f'/admin/usuario/{self.user.id}/excluir', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Usu\xc3\xa1rio desativado com sucesso!', response.data)  # Corrigido para UTF-8

        # Deslogar
        self.logout()

if __name__ == '__main__':
    unittest.main(verbosity=2)