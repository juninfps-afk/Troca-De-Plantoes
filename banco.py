import hashlib
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from werkzeug.security import generate_password_hash

PASTA = Path(__file__).resolve().parent / "instance"
# Os testes usam outro banco (variável PLANTOES_DB) para não mexer nos dados reais.
ARQUIVO = Path(os.environ.get("PLANTOES_DB", PASTA / "plantoes.db"))
FORMATO_DATA = "%Y-%m-%dT%H:%M"
DURACAO_SESSAO = 30 * 60  # 30 minutos, em segundos


@contextmanager
def conectar():
    PASTA.mkdir(exist_ok=True)
    db = sqlite3.connect(ARQUIVO)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# A tabela das trocas fica numa variável porque também é usada para atualizar bancos antigos.
SQL_TROCAS = """CREATE TABLE IF NOT EXISTS trocas (
    id INTEGER PRIMARY KEY,
    plantao_solicitante INTEGER NOT NULL REFERENCES plantoes(id),
    plantao_colega INTEGER NOT NULL REFERENCES plantoes(id),
    solicitante_id INTEGER NOT NULL REFERENCES usuarios(id),
    colega_id INTEGER NOT NULL REFERENCES usuarios(id),
    status TEXT NOT NULL CHECK(status IN ('aguardando_colega', 'aguardando_supervisor', 'aprovada',
                                          'recusada_colega', 'recusada_supervisor', 'cancelada')),
    empresa TEXT NOT NULL, criada_em TEXT NOT NULL
)"""


def _atualizar_tabela_trocas(db):
    # Bancos antigos não aceitam o status 'cancelada': recria a tabela copiando as linhas.
    linha = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='trocas'").fetchone()
    if linha is None or "cancelada" in linha["sql"]:
        return
    db.execute("BEGIN IMMEDIATE")
    db.execute("ALTER TABLE trocas RENAME TO trocas_antiga")
    db.execute(SQL_TROCAS)
    db.execute("INSERT INTO trocas SELECT * FROM trocas_antiga")
    db.execute("DROP TABLE trocas_antiga")


def criar_banco():
    with conectar() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY, nome TEXT NOT NULL, login TEXT NOT NULL UNIQUE, senha_hash TEXT NOT NULL,
            perfil TEXT NOT NULL CHECK(perfil IN ('funcionario','supervisor')), empresa TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessoes (
            token_hash TEXT PRIMARY KEY, expira_em INTEGER NOT NULL,
            usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS plantoes (
            id INTEGER PRIMARY KEY, funcionario_id INTEGER NOT NULL REFERENCES usuarios(id),
            inicio TEXT NOT NULL, termino TEXT NOT NULL, CHECK(termino > inicio)
        );
        -- Registro de ações: quem fez o quê, em qual item, com qual resultado e quando.
        CREATE TABLE IF NOT EXISTS registros (
            id INTEGER PRIMARY KEY, empresa TEXT NOT NULL, ator TEXT NOT NULL, acao TEXT NOT NULL,
            referencia TEXT NOT NULL, resultado TEXT NOT NULL, criado_em TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_plantao_funcionario ON plantoes(funcionario_id, inicio);
        CREATE INDEX IF NOT EXISTS idx_registros_empresa ON registros(empresa, id);
        -- Os registros só podem ser incluídos: o banco recusa alterar ou apagar.
        CREATE TRIGGER IF NOT EXISTS registros_sem_alteracao BEFORE UPDATE ON registros
        BEGIN SELECT RAISE(ABORT, 'Os registros não podem ser alterados.'); END;
        CREATE TRIGGER IF NOT EXISTS registros_sem_exclusao BEFORE DELETE ON registros
        BEGIN SELECT RAISE(ABORT, 'Os registros não podem ser apagados.'); END;
        """)
        _atualizar_tabela_trocas(db)
        db.execute(SQL_TROCAS)
        db.execute("CREATE INDEX IF NOT EXISTS idx_trocas_empresa_status ON trocas(empresa, status)")


# ---------- Registro de ações ----------
def registrar(empresa, ator, acao, referencia, resultado):
    # Guarda uma linha no registro. Nunca grava senhas.
    agora = datetime.now().isoformat(timespec="seconds")
    with conectar() as db:
        db.execute("INSERT INTO registros(empresa,ator,acao,referencia,resultado,criado_em) VALUES(?,?,?,?,?,?)",
                   (empresa, str(ator)[:50], acao, str(referencia)[:100], str(resultado)[:200], agora))


def listar_registros(empresa, limite=200):
    with conectar() as db:
        return db.execute("SELECT * FROM registros WHERE empresa=? ORDER BY id DESC LIMIT ?",
                          (empresa, limite)).fetchall()


# ---------- Login e sessões ----------
def buscar_login(login):
    with conectar() as db:
        return db.execute("SELECT * FROM usuarios WHERE login = ?", (login,)).fetchone()


def _hash_do_token(token):
    # O banco guarda só o hash do token. Devolve None se o token não tiver o formato certo.
    if not isinstance(token, str) or len(token) != 43:
        return None
    return hashlib.sha256(token.encode()).hexdigest()


def criar_sessao(usuario_id):
    token = secrets.token_urlsafe(32)
    agora = int(time.time())
    with conectar() as db:
        db.execute("DELETE FROM sessoes WHERE expira_em <= ?", (agora,))
        db.execute("INSERT INTO sessoes VALUES (?, ?, ?)", (_hash_do_token(token), agora + DURACAO_SESSAO, usuario_id))
    return token


def buscar_sessao(token):
    token_hash = _hash_do_token(token)
    if token_hash is None:
        return None
    with conectar() as db:
        return db.execute("""SELECT u.id, u.nome, u.login, u.perfil, u.empresa
            FROM sessoes s JOIN usuarios u ON u.id = s.usuario_id
            WHERE s.token_hash = ? AND s.expira_em > ?""", (token_hash, int(time.time()))).fetchone()


def encerrar_sessao(token):
    token_hash = _hash_do_token(token)
    if token_hash is not None:
        with conectar() as db:
            db.execute("DELETE FROM sessoes WHERE token_hash = ?", (token_hash,))


# ---------- Funcionários ----------
def criar_funcionario(nome, login, senha, empresa):
    nome, login = nome.strip(), login.strip().lower()
    if not 2 <= len(nome) <= 100:
        raise ValueError("O nome deve ter entre 2 e 100 caracteres.")
    if not 3 <= len(login) <= 50 or any(c.isspace() for c in login):
        raise ValueError("O usuário deve ter entre 3 e 50 caracteres, sem espaços.")
    if not 15 <= len(senha) <= 128:
        raise ValueError("A senha deve ter entre 15 e 128 caracteres.")
    senha_hash = generate_password_hash(senha, method="scrypt")
    try:
        with conectar() as db:
            return db.execute(
                "INSERT INTO usuarios(nome,login,senha_hash,perfil,empresa) VALUES(?,?,?,'funcionario',?)",
                (nome, login, senha_hash, empresa),
            ).lastrowid
    except sqlite3.IntegrityError:
        raise ValueError("Não foi possível cadastrar. Confira se o usuário já existe.") from None


def listar_funcionarios(empresa):
    with conectar() as db:
        return db.execute("SELECT id, nome, login FROM usuarios WHERE perfil='funcionario' AND empresa=? ORDER BY nome",
                          (empresa,)).fetchall()


# ---------- Plantões ----------
def _data(valor):
    try:
        return datetime.strptime(valor, FORMATO_DATA)
    except (ValueError, TypeError):
        raise ValueError("Informe uma data e horário válidos.") from None


def _tem_conflito(db, funcionario_id, inicio, termino, ignorar_1=0, ignorar_2=0):
    # Procura outro plantão do funcionário que se sobreponha a esse intervalo.
    # Os dois "ignorar" são plantões que não contam (usado na troca). O id 0 não existe.
    achou = db.execute("""SELECT id FROM plantoes WHERE funcionario_id = ? AND id NOT IN (?, ?)
        AND inicio < ? AND termino > ?""", (funcionario_id, ignorar_1, ignorar_2, termino, inicio)).fetchone()
    return achou is not None


def criar_plantao(funcionario_id, inicio, termino, empresa):
    try:
        funcionario_id = int(funcionario_id)
    except (ValueError, TypeError):
        raise ValueError("Selecione um funcionário válido.") from None
    ini, fim = _data(inicio), _data(termino)
    if ini <= datetime.now():
        raise ValueError("O plantão deve começar no futuro.")
    if fim <= ini:
        raise ValueError("O término deve ser posterior ao início.")
    inicio, termino = ini.strftime(FORMATO_DATA), fim.strftime(FORMATO_DATA)
    with conectar() as db:
        db.execute("BEGIN IMMEDIATE")
        funcionario = db.execute("SELECT id FROM usuarios WHERE id=? AND perfil='funcionario' AND empresa=?",
                                 (funcionario_id, empresa)).fetchone()
        if not funcionario:
            raise ValueError("Selecione um funcionário válido da sua empresa.")
        if _tem_conflito(db, funcionario_id, inicio, termino):
            raise ValueError("Esse funcionário já tem um plantão nesse intervalo.")
        return db.execute("INSERT INTO plantoes(funcionario_id,inicio,termino) VALUES(?,?,?)",
                          (funcionario_id, inicio, termino)).lastrowid


def listar_plantoes(empresa):
    with conectar() as db:
        return db.execute("""SELECT p.id, p.funcionario_id, u.nome AS funcionario_nome, p.inicio, p.termino
            FROM plantoes p JOIN usuarios u ON u.id = p.funcionario_id
            WHERE u.empresa = ? ORDER BY p.inicio""", (empresa,)).fetchall()


def _buscar_plantao(db, plantao_id):
    # Plantão junto com a empresa do funcionário dono dele.
    return db.execute("""SELECT p.id, p.funcionario_id, p.inicio, p.termino, u.empresa
        FROM plantoes p JOIN usuarios u ON u.id = p.funcionario_id WHERE p.id = ?""", (plantao_id,)).fetchone()


# ---------- Trocas ----------
def _checar_troca_possivel(plantao_a, plantao_b):
    # Regras: só trocam plantões que ainda não começaram e que têm a mesma duração.
    ini_a, fim_a = (datetime.strptime(plantao_a[campo], FORMATO_DATA) for campo in ("inicio", "termino"))
    ini_b, fim_b = (datetime.strptime(plantao_b[campo], FORMATO_DATA) for campo in ("inicio", "termino"))
    if ini_a <= datetime.now() or ini_b <= datetime.now():
        raise ValueError("Só é possível trocar plantões que ainda não começaram.")
    if fim_a - ini_a != fim_b - ini_b:
        raise ValueError("Os dois plantões precisam ter a mesma duração.")


def _mudar_status(db, troca_id, status):
    db.execute("UPDATE trocas SET status = ? WHERE id = ?", (status, troca_id))


def criar_troca(meu_id, colega_plantao_id, solicitante_id, empresa):
    try:
        meu_id, colega_plantao_id = int(meu_id), int(colega_plantao_id)
    except (ValueError, TypeError):
        raise ValueError("Selecione dois plantões válidos.") from None
    if meu_id == colega_plantao_id:
        raise ValueError("Escolha dois plantões diferentes.")
    with conectar() as db:
        db.execute("BEGIN IMMEDIATE")
        meu, colega = _buscar_plantao(db, meu_id), _buscar_plantao(db, colega_plantao_id)
        pedido_valido = (
            meu and colega
            and meu["funcionario_id"] == solicitante_id        # o primeiro plantão é meu
            and colega["funcionario_id"] != solicitante_id     # o segundo é de outra pessoa
            and meu["empresa"] == colega["empresa"] == empresa  # os dois são da mesma empresa
        )
        if not pedido_valido:
            raise ValueError("Escolha seu plantão e o plantão de um colega da mesma empresa.")
        _checar_troca_possivel(meu, colega)
        repetida = db.execute("""SELECT id FROM trocas
            WHERE (plantao_solicitante IN (?, ?) OR plantao_colega IN (?, ?))
            AND status IN ('aguardando_colega', 'aguardando_supervisor')""",
                              (meu_id, colega_plantao_id, meu_id, colega_plantao_id)).fetchone()
        if repetida:
            raise ValueError("Um desses plantões já está em uma troca pendente.")
        return db.execute("""INSERT INTO trocas(plantao_solicitante, plantao_colega, solicitante_id, colega_id,
            status, empresa, criada_em) VALUES (?, ?, ?, ?, 'aguardando_colega', ?, ?)""",
                          (meu_id, colega_plantao_id, solicitante_id, colega["funcionario_id"],
                           empresa, datetime.now().isoformat(timespec="minutes"))).lastrowid


def listar_trocas(usuario_id, perfil, empresa):
    sql = """SELECT t.*, a.inicio AS inicio_a, a.termino AS termino_a, ua.nome AS nome_a,
        b.inicio AS inicio_b, b.termino AS termino_b, ub.nome AS nome_b
        FROM trocas t
        JOIN plantoes a ON a.id = t.plantao_solicitante JOIN usuarios ua ON ua.id = t.solicitante_id
        JOIN plantoes b ON b.id = t.plantao_colega JOIN usuarios ub ON ub.id = t.colega_id
        WHERE t.empresa = ?"""
    args = [empresa]
    if perfil != "supervisor":  # funcionário só vê as trocas em que participa
        sql += " AND (t.solicitante_id = ? OR t.colega_id = ?)"
        args += [usuario_id, usuario_id]
    with conectar() as db:
        return db.execute(sql + " ORDER BY t.id DESC", args).fetchall()


def responder_troca(troca_id, usuario_id, resposta, empresa):
    if resposta not in ("aceitar", "recusar"):
        raise ValueError("Resposta inválida.")
    with conectar() as db:
        db.execute("BEGIN IMMEDIATE")
        troca = db.execute("""SELECT id FROM trocas
            WHERE id = ? AND colega_id = ? AND empresa = ? AND status = 'aguardando_colega'""",
                           (troca_id, usuario_id, empresa)).fetchone()
        if not troca:
            raise ValueError("Essa solicitação não está disponível para você.")
        _mudar_status(db, troca_id, "aguardando_supervisor" if resposta == "aceitar" else "recusada_colega")


def decidir_troca(troca_id, decisao, empresa):
    if decisao not in ("aprovar", "recusar"):
        raise ValueError("Decisão inválida.")
    with conectar() as db:
        db.execute("BEGIN IMMEDIATE")
        troca = db.execute("SELECT * FROM trocas WHERE id = ? AND empresa = ? AND status = 'aguardando_supervisor'",
                           (troca_id, empresa)).fetchone()
        if not troca:
            raise ValueError("Essa troca não está aguardando aprovação.")
        if decisao == "recusar":
            _mudar_status(db, troca_id, "recusada_supervisor")
            return
        # Aprovar: confere tudo de novo, porque a escala pode ter mudado desde o pedido.
        a, b = _buscar_plantao(db, troca["plantao_solicitante"]), _buscar_plantao(db, troca["plantao_colega"])
        if not (a and b) or (a["funcionario_id"], b["funcionario_id"]) != (troca["solicitante_id"], troca["colega_id"]):
            raise ValueError("A escala mudou desde a solicitação. Não foi possível aprovar.")
        _checar_troca_possivel(a, b)
        # Depois da troca, cada um fica com o plantão do outro: não pode bater com os demais.
        for novo_dono, plantao in ((troca["colega_id"], a), (troca["solicitante_id"], b)):
            if _tem_conflito(db, novo_dono, plantao["inicio"], plantao["termino"], a["id"], b["id"]):
                raise ValueError("A troca criaria conflito com outro plantão. A escala não foi alterada.")
        db.execute("UPDATE plantoes SET funcionario_id = ? WHERE id = ?", (troca["colega_id"], a["id"]))
        db.execute("UPDATE plantoes SET funcionario_id = ? WHERE id = ?", (troca["solicitante_id"], b["id"]))
        _mudar_status(db, troca_id, "aprovada")


def cancelar_troca(troca_id, usuario_id, empresa):
    # Só quem pediu a troca cancela, e só enquanto ela está pendente.
    with conectar() as db:
        db.execute("BEGIN IMMEDIATE")
        troca = db.execute("""SELECT id FROM trocas WHERE id = ? AND solicitante_id = ? AND empresa = ?
            AND status IN ('aguardando_colega', 'aguardando_supervisor')""", (troca_id, usuario_id, empresa)).fetchone()
        if not troca:
            raise ValueError("Essa solicitação não pode ser cancelada por você.")
        _mudar_status(db, troca_id, "cancelada")
