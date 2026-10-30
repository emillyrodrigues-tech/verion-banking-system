import os
import sqlite3
import secrets
from decimal import Decimal, InvalidOperation

from functools import wraps
from flask import (
    Flask,
    request,
    session,
    redirect,
    url_for,
    flash,
    render_template_string,
    g
)
from werkzeug.security import generate_password_hash, check_password_hash


# --------------------------------------------------
# CONFIGURAÇÕES DA APLICAÇÃO
# --------------------------------------------------

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "chave-temporaria-apenas-para-desenvolvimento"
)

DATABASE = "verion.db"


# --------------------------------------------------
# CONEXÃO COM O BANCO DE DADOS
# --------------------------------------------------

def get_db():
    """Cria uma conexão com o banco de dados."""

    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")

    return g.db


@app.teardown_appcontext
def close_db(error=None):
    """Fecha a conexão ao finalizar a requisição."""

    db = g.pop("db", None)

    if db is not None:
        db.close()


def initialize_database():
    """Cria as tabelas necessárias para o sistema."""

    db = get_db()

    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            account_number TEXT NOT NULL UNIQUE,
            balance INTEGER NOT NULL DEFAULT 0
                CHECK (balance >= 0),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            transaction_type TEXT NOT NULL,
            amount INTEGER NOT NULL CHECK (amount > 0),
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (account_id) REFERENCES accounts(id)
        );
    """)

    db.commit()


# --------------------------------------------------
# SEGURANÇA E VALIDAÇÕES
# --------------------------------------------------

def login_required(function):
    """Impede o acesso às páginas sem autenticação."""

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:
            flash("Faça login para continuar.", "error")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return decorated_function


def create_csrf_token():
    """Gera um token para proteger formulários."""

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = create_csrf_token


@app.before_request
def validate_csrf():
    """Valida o token enviado pelos formulários."""

    if request.method == "POST":
        token = request.form.get("csrf_token", "")

        if not secrets.compare_digest(
            token,
            session.get("csrf_token", "")
        ):
            return "Solicitação inválida. Atualize a página.", 400


def convert_to_cents(value):
    """Converte um valor monetário em reais para centavos."""

    try:
        amount = Decimal(value.replace(",", "."))

        if not amount.is_finite():
            return None

        if amount <= 0:
            return None

        if amount.as_tuple().exponent < -2:
            return None

        return int(amount * 100)

    except (InvalidOperation, AttributeError, ValueError):
        return None


def format_money(value):
    """Formata centavos para reais."""

    amount = Decimal(value) / Decimal(100)

    return f"R$ {amount:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


app.jinja_env.filters["money"] = format_money


# --------------------------------------------------
# CONSULTAS DO USUÁRIO
# --------------------------------------------------

def get_account(user_id):
    """Busca a conta bancária do usuário."""

    db = get_db()

    return db.execute("""
        SELECT *
        FROM accounts
        WHERE user_id = ?
    """, (user_id,)).fetchone()


# --------------------------------------------------
# PÁGINAS HTML
# --------------------------------------------------

BASE_HTML = """
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VÉRION Banking System</title>

    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f2f4f7;
            margin: 0;
            padding: 30px;
            color: #222;
        }

        .container {
            max-width: 650px;
            margin: auto;
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 3px 12px rgba(0,0,0,0.08);
        }

        h1 {
            color: #172b4d;
        }

        input, button {
            width: 100%;
            padding: 12px;
            margin: 8px 0;
            box-sizing: border-box;
        }

        button {
            background: #172b4d;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
        }

        a {
            color: #2457a7;
            text-decoration: none;
        }

        .message {
            padding: 10px;
            background: #f0f2f5;
            margin: 10px 0;
            border-radius: 5px;
        }

        .saldo {
            font-size: 25px;
            font-weight: bold;
            color: #172b4d;
        }

        .menu a {
            display: inline-block;
            margin: 8px;
        }
    </style>
</head>

<body>
    <div class="container">

        <h1>VÉRION</h1>
        <p>Banking System</p>

        {% for category, message in get_flashed_messages(with_categories=true) %}
            <div class="message">{{ message }}</div>
        {% endfor %}

        {{ content | safe }}

    </div>
</body>
</html>
"""


# --------------------------------------------------
# CADASTRO
# --------------------------------------------------

@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("Preencha todos os campos.", "error")

        elif len(password) < 8:
            flash("A senha precisa ter pelo menos 8 caracteres.", "error")

        else:
            db = get_db()

            try:
                with db:

                    cursor = db.execute("""
                        INSERT INTO users (name, email, password)
                        VALUES (?, ?, ?)
                    """, (
                        name,
                        email,
                        generate_password_hash(password)
                    ))

                    user_id = cursor.lastrowid

                    account_number = secrets.token_hex(4).upper()

                    db.execute("""
                        INSERT INTO accounts (
                            user_id,
                            account_number,
                            balance
                        )
                        VALUES (?, ?, 0)
                    """, (
                        user_id,
                        account_number
                    ))

                flash("Cadastro realizado com sucesso!", "success")
                return redirect(url_for("login"))

            except sqlite3.IntegrityError:
                flash("Este e-mail já está cadastrado.", "error")

    content = """
        <h2>Criar conta</h2>

        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

            <input type="text" name="name"
                placeholder="Nome completo" required>

            <input type="email" name="email"
                placeholder="E-mail" required>

            <input type="password" name="password"
                placeholder="Senha (mínimo 8 caracteres)" required>

            <button type="submit">Cadastrar</button>
        </form>

        <p>Já possui uma conta?
            <a href="{{ url_for('login') }}">Entrar</a>
        </p>
    """

    return render_template_string(BASE_HTML, content=content)


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()

        user = db.execute("""
            SELECT *
            FROM users
            WHERE email = ?
        """, (email,)).fetchone()

        if user and check_password_hash(user["password"], password):

            session.clear()
            session["user_id"] = user["id"]
            create_csrf_token()

            return redirect(url_for("dashboard"))

        flash("E-mail ou senha incorretos.", "error")

    content = """
        <h2>Acessar conta</h2>

        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

            <input type="email" name="email"
                placeholder="E-mail" required>

            <input type="password" name="password"
                placeholder="Senha" required>

            <button type="submit">Entrar</button>
        </form>

        <p>Não possui uma conta?
            <a href="{{ url_for('cadastro') }}">Cadastre-se</a>
        </p>
    """

    return render_template_string(BASE_HTML, content=content)


# --------------------------------------------------
# PAINEL PRINCIPAL
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    db = get_db()

    user = db.execute("""
        SELECT name
        FROM users
        WHERE id = ?
    """, (session["user_id"],)).fetchone()

    account = get_account(session["user_id"])

    content = """
        <h2>Olá, {{ user["name"] }}!</h2>

        <p>Bem-vindo ao seu painel financeiro.</p>

        <p>Conta: {{ account["account_number"] }}</p>

        <p>Saldo disponível:</p>

        <div class="saldo">
            {{ account["balance"] | money }}
        </div>

        <div class="menu">
            <a href="{{ url_for('deposito') }}">Depósito</a>
            <a href="{{ url_for('saque') }}">Saque</a>
            <a href="{{ url_for('transferencia') }}">Transferência</a>
            <a href="{{ url_for('extrato') }}">Extrato</a>
            <a href="{{ url_for('logout') }}">Sair</a>
        </div>
    """

    return render_template_string(
        BASE_HTML,
        content=content,
        user=user,
        account=account
    )


# --------------------------------------------------
# DEPÓSITO
# --------------------------------------------------

@app.route("/deposito", methods=["GET", "POST"])
@login_required
def deposito():

    if request.method == "POST":

        amount = convert_to_cents(
            request.form.get("amount", "")
        )

        if amount is None:
            flash("Informe um valor válido.", "error")

        else:
            db = get_db()
            account = get_account(session["user_id"])

            with db:
                db.execute("""
                    UPDATE accounts
                    SET balance = balance + ?
                    WHERE id = ?
                """, (amount, account["id"]))

                db.execute("""
                    INSERT INTO transactions (
                        account_id,
                        transaction_type,
                        amount,
                        description
                    )
                    VALUES (?, ?, ?, ?)
                """, (
                    account["id"],
                    "DEPOSITO",
                    amount,
                    "Depósito realizado"
                ))

            flash("Depósito realizado com sucesso!", "success")
            return redirect(url_for("dashboard"))

    content = """
        <h2>Realizar depósito</h2>

        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

            <input type="text" name="amount"
                placeholder="Valor em reais (ex.: 100,00)" required>

            <button type="submit">Depositar</button>
        </form>

        <a href="{{ url_for('dashboard') }}">Voltar</a>
    """

    return render_template_string(BASE_HTML, content=content)


# --------------------------------------------------
# SAQUE
# --------------------------------------------------

@app.route("/saque", methods=["GET", "POST"])
@login_required
def saque():

    if request.method == "POST":

        amount = convert_to_cents(
            request.form.get("amount", "")
        )

        if amount is None:
            flash("Informe um valor válido.", "error")

        else:
            db = get_db()
            account = get_account(session["user_id"])

            with db:
                cursor = db.execute("""
                    UPDATE accounts
                    SET balance = balance - ?
                    WHERE id = ? AND balance >= ?
                """, (
                    amount,
                    account["id"],
                    amount
                ))

                if cursor.rowcount == 0:
                    flash("Saldo insuficiente.", "error")
                    return redirect(url_for("saque"))

                db.execute("""
                    INSERT INTO transactions (
                        account_id,
                        transaction_type,
                        amount,
                        description
                    )
                    VALUES (?, ?, ?, ?)
                """, (
                    account["id"],
                    "SAQUE",
                    amount,
                    "Saque realizado"
                ))

            flash("Saque realizado com sucesso!", "success")
            return redirect(url_for("dashboard"))

    content = """
        <h2>Realizar saque</h2>

        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

            <input type="text" name="amount"
                placeholder="Valor em reais (ex.: 50,00)" required>

            <button type="submit">Sacar</button>
        </form>

        <a href="{{ url_for('dashboard') }}">Voltar</a>
    """

    return render_template_string(BASE_HTML, content=content)


# --------------------------------------------------
# TRANSFERÊNCIA
# --------------------------------------------------

@app.route("/transferencia", methods=["GET", "POST"])
@login_required
def transferencia():

    if request.method == "POST":

        destination_number = request.form.get(
            "account_number", ""
        ).strip().upper()

        amount = convert_to_cents(
            request.form.get("amount", "")
        )

        if not destination_number or amount is None:
            flash("Informe uma conta e um valor válido.", "error")

        else:
            db = get_db()
            origin = get_account(session["user_id"])

            destination = db.execute("""
                SELECT *
                FROM accounts
                WHERE account_number = ?
            """, (destination_number,)).fetchone()

            if destination is None:
                flash("Conta de destino não encontrada.", "error")

            elif destination["id"] == origin["id"]:
                flash("Não é possível transferir para a própria conta.", "error")

            else:
                try:
                    with db:

                        cursor = db.execute("""
                            UPDATE accounts
                            SET balance = balance - ?
                            WHERE id = ? AND balance >= ?
                        """, (
                            amount,
                            origin["id"],
                            amount
                        ))

                        if cursor.rowcount == 0:
                            raise ValueError("Saldo insuficiente.")

                        db.execute("""
                            UPDATE accounts
                            SET balance = balance + ?
                            WHERE id = ?
                        """, (amount, destination["id"]))

                        db.execute("""
                            INSERT INTO transactions (
                                account_id,
                                transaction_type,
                                amount,
                                description
                            )
                            VALUES (?, ?, ?, ?)
                        """, (
                            origin["id"],
                            "TRANSFERENCIA_ENVIADA",
                            amount,
                            f"Transferência para {destination_number}"
                        ))

                        db.execute("""
                            INSERT INTO transactions (
                                account_id,
                                transaction_type,
                                amount,
                                description
                            )
                            VALUES (?, ?, ?, ?)
                        """, (
                            destination["id"],
                            "TRANSFERENCIA_RECEBIDA",
                            amount,
                            f"Transferência recebida de {origin['account_number']}"
                        ))

                    flash("Transferência realizada com sucesso!", "success")
                    return redirect(url_for("dashboard"))

                except ValueError as error:
                    flash(str(error), "error")

    content = """
        <h2>Realizar transferência</h2>

        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

            <input type="text" name="account_number"
                placeholder="Número da conta de destino" required>

            <input type="text" name="amount"
                placeholder="Valor em reais (ex.: 100,00)" required>

            <button type="submit">Transferir</button>
        </form>

        <a href="{{ url_for('dashboard') }}">Voltar</a>
    """

    return render_template_string(BASE_HTML, content=content)


# --------------------------------------------------
# EXTRATO
# --------------------------------------------------

@app.route("/extrato")
@login_required
def extrato():

    db = get_db()
    account = get_account(session["user_id"])

    transactions = db.execute("""
        SELECT *
        FROM transactions
        WHERE account_id = ?
        ORDER BY created_at DESC, id DESC
    """, (account["id"],)).fetchall()

    content = """
        <h2>Extrato bancário</h2>

        {% if transactions %}
            {% for transaction in transactions %}
                <div class="message">
                    <strong>{{ transaction["transaction_type"] }}</strong>

                    <p>{{ transaction["description"] }}</p>

                    <p>{{ transaction["amount"] | money }}</p>

                    <small>{{ transaction["created_at"] }}</small>
                </div>
            {% endfor %}
        {% else %}
            <p>Nenhuma movimentação encontrada.</p>
        {% endif %}

        <a href="{{ url_for('dashboard') }}">Voltar</a>
    """

    return render_template_string(
        BASE_HTML,
        content=content,
        transactions=transactions
    )


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
@login_required
def logout():

    session.clear()

    flash("Você saiu da sua conta.", "success")

    return redirect(url_for("login"))


# --------------------------------------------------
# EXECUÇÃO DA APLICAÇÃO
# --------------------------------------------------

if __name__ == "__main__":

    with app.app_context():
        initialize_database()

    app.run(debug=True)