# Troca de Plantões

Sistema web para gerenciar escalas de plantão e pedidos de troca entre funcionários, com aprovação do supervisor.

Projeto acadêmico da disciplina de **Desenvolvimento de Software Seguro**.

**Tecnologias:** Python, Flask, SQLite, HTML e CSS, Flask-WTF (proteção CSRF) e Flask-Limiter (limite de tentativas).

---

## O que o sistema faz

Existem dois perfis de usuário:

| Perfil | O que pode fazer |
|---|---|
| **Supervisor** | Cadastrar funcionários e plantões, aprovar ou recusar trocas e consultar o registro de ações |
| **Funcionário** | Consultar a escala, pedir troca de plantão, aceitar ou recusar pedidos de colegas e cancelar os próprios pedidos |

### Como funciona uma troca

1. O funcionário **solicita** a troca de um plantão seu por um plantão de um colega.
2. O colega **aceita ou recusa**.
3. Se o colega aceitar, o supervisor **aprova ou recusa**.
4. A escala **só muda depois da aprovação** do supervisor.

O solicitante pode **cancelar** o pedido enquanto ele estiver pendente.

### Regras da troca

- Só podem ser trocados plantões que **ainda não começaram**.
- Os dois plantões precisam ter a **mesma duração**.

---

## Medidas de segurança

- **Senhas** guardadas apenas como hash (`scrypt`), com tamanho obrigatório de 15 a 128 caracteres. A senha nunca é gravada em texto nem no registro de ações.
- **Limite de tentativas de login:** no máximo 5 tentativas por minuto.
- **Mensagem de erro genérica** no login ("Usuário ou senha inválidos"), sem revelar se o usuário existe. Para usuários inexistentes, o sistema confere um hash falso, para o tempo de resposta ser parecido.
- **Proteção CSRF** em todos os formulários (Flask-WTF).
- **Sessões** com token aleatório; no banco fica só o hash do token. Elas expiram em 30 minutos e são apagadas no logout.
- **Cookies de sessão** com `HttpOnly` e `SameSite=Lax`.
- **Controle de acesso por perfil:** rotas do supervisor devolvem erro 403 para quem não é supervisor, e a tentativa fica registrada.
- **Registro de ações** (login, falhas, trocas, acessos negados), que o supervisor consulta em "Ver registros de ações".
- **Limite de 1 MB** por requisição.
- **Chave secreta** criada automaticamente na primeira execução e guardada em `instance/`, fora do repositório (veja o `.gitignore`).

> Para uso em produção, ative `SESSION_COOKIE_SECURE=True` no `app.py` e use HTTPS.

---

## Como rodar

**Requisito:** Python 3.11 ou mais recente.

```powershell
# 1. Clone o repositório e entre na pasta
git clone https://github.com/juninfps-afk/Troca-De-Plantoes.git
cd Troca-De-Plantoes

# 2. (Recomendado) Crie e ative um ambiente virtual
py -m venv .venv
.venv\Scripts\activate

# 3. Instale as bibliotecas
py -m pip install -r requirements.txt

# 4. Crie o primeiro supervisor (nome, usuário, empresa/equipe e senha de 15 a 128 caracteres)
py criar_supervisor.py

# 5. Inicie o sistema
py app.py
```

Depois, abra **http://127.0.0.1:5000** no navegador e entre com o supervisor criado.

Se esquecer a senha do supervisor, rode `redefinir_supervisor.py`.

---

## Estrutura do projeto

```
├── app.py                    # Rotas, login, sessão e regras de acesso
├── banco.py                  # Banco de dados SQLite e regras das trocas
├── criar_supervisor.py       # Cria o primeiro supervisor
├── redefinir_supervisor.py   # Redefine a senha de um supervisor
├── requirements.txt          # Bibliotecas necessárias
├── templates/                # Páginas HTML
├── static/                   # CSS
└── instance/                 # Banco de dados e chave secreta (não vão para o GitHub)
```

---

## Autores

- Roberto Bezerra
- Éder Vinicius
