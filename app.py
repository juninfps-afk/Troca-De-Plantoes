from datetime import datetime
from functools import wraps
from pathlib import Path
import secrets
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from banco import (
    FORMATO_DATA, criar_banco, buscar_login, criar_sessao, buscar_sessao, encerrar_sessao,
    criar_funcionario, listar_funcionarios, criar_plantao, listar_plantoes,
    criar_troca, listar_trocas, responder_troca, decidir_troca, cancelar_troca,
    registrar, listar_registros,
)

# A chave secreta é criada sozinha na primeira vez e fica em instance/.
INSTANCE = Path(__file__).resolve().parent / "instance"
INSTANCE.mkdir(exist_ok=True)
chave = INSTANCE / "chave_secreta.txt"
if not chave.exists():
    chave.write_text(secrets.token_hex(32), encoding="utf-8")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=chave.read_text(encoding="utf-8").strip(),
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # mude para True quando usar HTTPS
    MAX_CONTENT_LENGTH=1024 * 1024,  # no máximo 1 MB por requisição
)
CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=[])
HASH_FICTICIO = generate_password_hash(secrets.token_urlsafe(24), method="scrypt")
criar_banco()

NOMES_STATUS = {
    "aguardando_colega": "Aguardando colega", "aguardando_supervisor": "Aguardando supervisor",
    "aprovada": "Aprovada", "recusada_colega": "Recusada pelo colega",
    "recusada_supervisor": "Recusada pelo supervisor", "cancelada": "Cancelada pelo solicitante",
}


# ---------- Filtros usados nos templates ----------
@app.template_filter("data_hora")
def data_hora(texto, separador=" às "):
    # Mostra "2026-11-03T08:00" como "2026-11-03 às 08:00".
    return texto.replace("T", separador)


@app.template_filter("nome_status")
def nome_status(status):
    return NOMES_STATUS.get(status, status)


# ---------- Proteção das rotas ----------
def login_obrigatorio(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        usuario = buscar_sessao(session.get("token"))
        if usuario is None:
            session.clear()
            return redirect(url_for("login"))
        g.usuario = usuario
        return func(*args, **kwargs)
    return wrapper


def supervisor_obrigatorio(func):
    @wraps(func)
    @login_obrigatorio
    def wrapper(*args, **kwargs):
        if g.usuario["perfil"] != "supervisor":
            anotar("acesso negado", request.path, "negado: não é supervisor")
            abort(403)
        return func(*args, **kwargs)
    return wrapper


# ---------- Ajudantes para registrar as ações ----------
def anotar(acao, referencia, resultado="sucesso"):
    # Anota no registro uma ação de quem está logado.
    registrar(g.usuario["empresa"], g.usuario["login"], acao, referencia, resultado)


def tentar(acao, funcao, *args):
    # Roda uma função do banco. Se der erro, mostra na tela, anota a falha e devolve None.
    try:
        return funcao(*args)
    except ValueError as erro:
        anotar(acao, "-", f"falha: {erro}")
        flash(str(erro), "erro")


def executar(acao, troca_id, mensagem, funcao, *args, detalhe=""):
    # Faz uma ação sobre uma troca, avisa o usuário na tela e anota o resultado no registro.
    try:
        funcao(troca_id, *args)
    except ValueError as erro:
        anotar(acao, f"troca {troca_id}", f"falha: {erro}")
        flash(str(erro), "erro")
    else:
        anotar(acao, f"troca {troca_id}", "sucesso" + detalhe)
        flash(mensagem, "sucesso")
    return redirect(url_for("trocas"))


# ---------- Entrada e saída ----------
@app.route("/")
def inicio():
    return render_template("inicio.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        login_digitado = request.form.get("login", "").strip().lower()
        senha = request.form.get("senha", "")
        usuario = buscar_login(login_digitado) if 3 <= len(login_digitado) <= 50 else None
        # Se o usuário não existe, confere com um hash falso para demorar o mesmo tempo.
        hash_senha = usuario["senha_hash"] if usuario else HASH_FICTICIO
        senha_ok = 1 <= len(senha) <= 128 and check_password_hash(hash_senha, senha)
        if usuario is None or not senha_ok:
            if usuario:  # só registra se o usuário existe (a senha digitada nunca é gravada)
                registrar(usuario["empresa"], usuario["login"], "login", "-", "falha: senha incorreta")
            flash("Usuário ou senha inválidos.", "erro")
            return render_template("login.html"), 401
        session.clear()
        session["token"] = criar_sessao(usuario["id"])
        registrar(usuario["empresa"], usuario["login"], "login", "-", "sucesso")
        return redirect(url_for("painel"))
    return render_template("login.html")


@app.post("/sair")
@login_obrigatorio
def sair():
    anotar("logout", "-")
    encerrar_sessao(session.get("token"))
    session.clear()
    return redirect(url_for("login"))


@app.route("/painel")
@login_obrigatorio
def painel():
    return render_template("painel.html", usuario=g.usuario)


# ---------- Cadastros (só supervisor) ----------
@app.route("/funcionarios/novo", methods=["GET", "POST"])
@supervisor_obrigatorio
def novo_funcionario():
    if request.method == "POST":
        campo = request.form.get
        if campo("senha") != campo("confirmacao"):
            flash("As senhas não conferem.", "erro")
        else:
            novo_id = tentar("criar funcionário", criar_funcionario, campo("nome", ""), campo("login", ""),
                             campo("senha", ""), g.usuario["empresa"])
            if novo_id:
                anotar("criar funcionário", f"funcionário {novo_id}")
                flash("Funcionário cadastrado.", "sucesso")
                return redirect(url_for("novo_funcionario"))
    return render_template("novo_funcionario.html")


@app.route("/plantoes/novo", methods=["GET", "POST"])
@supervisor_obrigatorio
def novo_plantao():
    if request.method == "POST":
        campo = request.form.get
        novo_id = tentar("criar plantão", criar_plantao, campo("funcionario_id", ""), campo("inicio", ""),
                         campo("termino", ""), g.usuario["empresa"])
        if novo_id:
            anotar("criar plantão", f"plantão {novo_id}")
            flash("Plantão cadastrado.", "sucesso")
            return redirect(url_for("escala"))
    return render_template("novo_plantao.html", funcionarios=listar_funcionarios(g.usuario["empresa"]))


# ---------- Escala e trocas ----------
@app.route("/escala")
@login_obrigatorio
def escala():
    return render_template("escala.html", plantoes=listar_plantoes(g.usuario["empresa"]), usuario=g.usuario)


@app.route("/trocas", methods=["GET", "POST"])
@login_obrigatorio
def trocas():
    usuario = g.usuario
    if request.method == "POST":
        campo = request.form.get
        novo_id = tentar("solicitar troca", criar_troca, campo("meu_plantao", ""), campo("plantao_colega", ""),
                         usuario["id"], usuario["empresa"])
        if novo_id:
            anotar("solicitar troca", f"troca {novo_id}")
            flash("Solicitação enviada ao colega.", "sucesso")
            return redirect(url_for("trocas"))
    return render_template(
        "trocas.html",
        trocas=listar_trocas(usuario["id"], usuario["perfil"], usuario["empresa"]),
        plantoes=listar_plantoes(usuario["empresa"]),
        usuario=usuario,
        agora=datetime.now().strftime(FORMATO_DATA),  # a tela só oferece plantões futuros
    )


@app.post("/trocas/<int:troca_id>/responder")
@login_obrigatorio
def responder(troca_id):
    resposta = request.form.get("resposta", "")
    return executar("responder troca", troca_id, "Resposta registrada.", responder_troca,
                    g.usuario["id"], resposta, g.usuario["empresa"], detalhe=f": {resposta}")


@app.post("/trocas/<int:troca_id>/decidir")
@supervisor_obrigatorio
def decidir(troca_id):
    decisao = request.form.get("decisao", "")
    return executar("decidir troca", troca_id, "Decisão registrada.", decidir_troca,
                    decisao, g.usuario["empresa"], detalhe=f": {decisao}")


@app.post("/trocas/<int:troca_id>/cancelar")
@login_obrigatorio
def cancelar(troca_id):
    return executar("cancelar troca", troca_id, "Solicitação cancelada.", cancelar_troca,
                    g.usuario["id"], g.usuario["empresa"])


@app.route("/registros")
@supervisor_obrigatorio
def registros():
    return render_template("registros.html", registros=listar_registros(g.usuario["empresa"]))


@app.errorhandler(403)
def proibido(_):
    return render_template("erro.html", mensagem="Você não tem permissão para acessar esta página."), 403


if __name__ == "__main__":
    app.run(debug=False)
