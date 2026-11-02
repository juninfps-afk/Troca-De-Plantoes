from getpass import getpass
import sqlite3
from werkzeug.security import generate_password_hash
from banco import criar_banco, conectar

criar_banco()
nome = input("Nome do supervisor: ").strip()
login = input("Usuário: ").strip().lower()
empresa = input("Nome da empresa/equipe: ").strip()
senha = getpass("Senha (15 a 128 caracteres): ")
confirmacao = getpass("Repita a senha: ")
if not 2 <= len(nome) <= 100 or not 3 <= len(login) <= 50 or any(c.isspace() for c in login) or not empresa or len(empresa) > 100:
    raise SystemExit("Confira nome, usuário e empresa.")
if not 15 <= len(senha) <= 128 or senha != confirmacao:
    raise SystemExit("A senha deve ter 15 a 128 caracteres e as confirmações precisam coincidir.")
try:
    with conectar() as db:
        db.execute("INSERT INTO usuarios(nome,login,senha_hash,perfil,empresa) VALUES(?,?,?,'supervisor',?)", (nome,login,generate_password_hash(senha,method="scrypt"),empresa))
except sqlite3.IntegrityError:
    raise SystemExit("Esse usuário já existe.")
print("Supervisor criado com sucesso para a empresa/equipe informada.")
