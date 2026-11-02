from getpass import getpass
from werkzeug.security import generate_password_hash
from banco import conectar
with conectar() as db:
    usuario = db.execute("SELECT id,login FROM usuarios WHERE perfil='supervisor'").fetchone()
    if not usuario:
        raise SystemExit("Nenhum supervisor encontrado.")
    print("Supervisor:", usuario['login'])
    senha = getpass("Nova senha (15 a 128 caracteres): ")
    confirmar = getpass("Repita a senha: ")
    if not 15 <= len(senha) <= 128 or senha != confirmar:
        raise SystemExit("Senha inválida ou confirmação diferente.")
    db.execute("UPDATE usuarios SET senha_hash=? WHERE id=?", (generate_password_hash(senha,method='scrypt'), usuario['id']))
    db.execute("DELETE FROM sessoes WHERE usuario_id=?", (usuario['id'],))
print("Senha alterada; sessões anteriores encerradas.")
