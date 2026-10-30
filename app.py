import os
import secrets
import sqlite3

from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from functools import wraps

from flask import (
    Flask,
    g,
    render_template_string,
    request,
    redirect,
    url_for,
    session,
    flash
)

from markupsafe import Markup
from werkzeug.security import generate_password_hash, check_password_hash

from database import get_connection, initialize_database


app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "chave-de-desenvolvimento-verion"
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# CONEXÃO COM O BANCO DE DADOS

def get_db():
    if "db" not in g:
        g.db = get_connection()

    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)

    if db is not None:
        db.close()


# FUNÇÕES AUXILIARES

def convert_to_cents(value):
    try:
        amount = Decimal(value.replace(",", "."))

        if not amount.is_finite() or amount <= 0:
            return None

        cents = (amount * 100).quantize(
            Decimal("1"),
            rounding=ROUND_HALF_UP
        )

        return int(cents)

    except (InvalidOperation, ValueError, AttributeError):
        return None


def format_money(cents):
    value = Decimal(cents) / 100

    formatted = f"{value:,.2f}"

    formatted = formatted.replace(",", "X")
    formatted = formatted.replace(".", ",")
    formatted = formatted.replace("X", ".")

    return f"R$ {formatted}"


def get_account():
    db = get_db()

    return db.execute(
        """
        SELECT *
        FROM accounts
        WHERE user_id = ?
        """,
        (session["user_id"],)
    ).fetchone()


# PROTEÇÃO CONTRA ACESSO NÃO AUTORIZADO

def login_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:
            flash("Faça login para continuar.", "error")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return decorated_function


# PROTEÇÃO CONTRA REQUISIÇÕES FALSIFICADAS

def csrf_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):

        token = session.get("csrf_token")
        submitted_token = request.form.get("csrf_token")

        if not token or token != submitted_token:
            flash("Solicitação inválida. Tente novamente.", "error")
            return redirect(request.referrer or url_for("login"))

        return function(*args, **kwargs)

    return decorated_function


@app.before_request
def create_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)


# MODELO VISUAL DAS PÁGINAS

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
            background: #101827;
            color: white;
            margin: 0;
            padding: 30px 15px;
        }

        .container {
            max-width: 500px;
            margin: auto;
            background: #1c293b;
            padding: 30px;
            border-radius: 12px;
        }

        h1, h2 {
            color: #d6b66b;
        }

        input, button {
            width: 100%;
            box-sizing: border-box;
            padding: 12px;
            margin: 8px 0;
            border-radius: 6px;
            border: none;
        }

        button {
            background: #d6b66b;
            color: #101827;
            font-weight: bold;
            cursor: pointer;
        }

        a {
            color: #d6b66b;
        }

        .balance {
            font-size: 28px;
            color: #d6b66b;
        }

        .message {
            padding: 10px;
            background: #34445b;
            border-radius: 6px;
            margin-bottom: 10px;
        }

        .transaction {
            border-bottom: 1px solid #40516a;
            padding: 10px 0;
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

        {% for category, message in messages %}
            <div class="message">{{ message }}</div>
        {% endfor %}

        {{ content }}

    </div>

</body>
</html>
"""


def render_page(template, **context):
    content = render_template_string(template, **context)

    messages = [
        (category, message)
        for category, message in get_flashed_messages()
    ]

    return render_template_string(
        BASE_HTML,
        content=Markup(content),
        messages=messages
    )


from flask import get_flashed_messages


# CADASTRO

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        if request.form.get("csrf_token") != session.get("csrf_token"):
            flash("Solicitação inválida.", "error")
            return redirect(url_for("register"))

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or len(password) < 8:
            flash("Preencha os campos corretamente. A senha precisa ter pelo menos 8 caracteres.", "error")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        db = get_db()

        try:
            with db:
                cursor = db.execute(
                    """
                    INSERT INTO users (name, email, password_hash)
                    VALUES (?, ?, ?)
                    """,
                    (name, email, password_hash)
                )

                user_id = cursor.lastrowid

                account_number = secrets.token_hex(4).upper()

                db.execute(
                    """
                    INSERT INTO accounts
                    (user_id, account_number, balance_cents)
                    VALUES (?, ?, 0)
                    """,
                    (user_id, account_number)
                )

            flash("Cadastro realizado com sucesso!", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Este e-mail já está cadastrado.", "error")

    return render_page("""
        <h2>Criar conta</h2>

        <form method="POST">

            <input type="hidden" name="csrf_token" value="{{ session['csrf_token'] }}">

            <input name="name" placeholder="Nome completo" required>

            <input name="email" type="email" placeholder="E-mail" required>

            <input name="password" type="password"
                   placeholder="Senha (mínimo 8 caracteres)"
                   minlength="8" required>

            <button type="submit">Cadastrar</button>

        </form>

        <p>Já possui conta? <a href="{{ url_for('login') }}">Entrar</a></p>
    """)


# LOGIN

@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        if request.form.get("csrf_token") != session.get("csrf_token"):
            flash("Solicitação inválida.", "error")
            return redirect(url_for("login"))

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()

        user = db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):

            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_hex(32)

            return redirect(url_for("dashboard"))

        flash("E-mail ou senha incorretos.", "error")

    return render_page("""
        <h2>Acessar conta</h2>

        <form method="POST">

            <input type="hidden" name="csrf_token" value="{{ session['csrf_token'] }}">

            <input name="email" type="email" placeholder="E-mail" required>

            <input name="password" type="password" placeholder="Senha" required>

            <button type="submit">Entrar</button>

        </form>

        <p>Não possui conta? <a href="{{ url_for('register') }}">Cadastre-se</a></p>
    """)


# PAINEL PRINCIPAL

@app.route("/dashboard")
@login_required
def dashboard():

    db = get_db()

    user = db.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    account = get_account()

    return render_page("""
        <h2>Olá, {{ user['name'] }}!</h2>

        <p>Seu saldo disponível:</p>

        <div class="balance">
            {{ balance }}
        </div>

        <p>Conta: {{ account['account_number'] }}</p>

        <div class="menu">
            <a href="{{ url_for('deposit') }}">Depositar</a>
            <a href="{{ url_for('withdraw') }}">Sacar</a>
            <a href="{{ url_for('transfer') }}">Transferir</a>
            <a href="{{ url_for('history') }}">Extrato</a>
        </div>

        <form method="POST" action="{{ url_for('logout') }}">
            <input type="hidden" name="csrf_token" value="{{ session['csrf_token'] }}">
            <button type="submit">Sair</button>
        </form>
    """,
        user=user,
        account=account,
        balance=format_money(account["balance_cents"])
    )


# DEPÓSITO

@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():

    if request.method == "POST":

        if request.form.get("csrf_token") != session.get("csrf_token"):
            flash("Solicitação inválida.", "error")
            return redirect(url_for("deposit"))

        amount = convert_to_cents(request.form.get("amount", ""))

        if amount is None:
            flash("Digite um valor válido.", "error")
            return redirect(url_for("deposit"))

        db = get_db()
        account = get_account()

        with db:
            db.execute(
                """
                UPDATE accounts
                SET balance_cents = balance_cents + ?
                WHERE id = ?
                """,
                (amount, account["id"])
            )

            db.execute(
                """
                INSERT INTO transactions
                (account_id, transaction_type, amount_cents, description)
                VALUES (?, 'deposit', ?, 'Depósito')
                """,
                (account["id"], amount)
            )

        flash("Depósito realizado com sucesso!", "success")
        return redirect(url_for("dashboard"))

    return render_page("""
        <h2>Depositar</h2>

        <form method="POST">

            <input type="hidden" name="csrf_token" value="{{ session['csrf_token'] }}">

            <input name="amount" placeholder="Valor do depósito" required>

            <button type="submit">Confirmar depósito</button>

        </form>

        <a href="{{ url_for('dashboard') }}">Voltar</a>
    """)


# SAQUE

@app.route("/withdraw", methods=["GET", "POST"])
@login_required
def withdraw():

    if request.method == "POST":

        if request.form.get("csrf_token") != session.get("csrf_token"):
            flash("Solicitação inválida.", "error")
            return redirect(url_for("withdraw"))

        amount = convert_to_cents(request.form.get("amount", ""))

        if amount is None:
            flash("Digite um valor válido.", "error")
            return redirect(url_for("withdraw"))

        db = get_db()
        account = get_account()

        with db:
            result = db.execute(
                """
                UPDATE accounts
                SET balance_cents = balance_cents - ?
                WHERE id = ? AND balance_cents >= ?
                """,
                (amount, account["id"], amount)
            )

            if result.rowcount == 0:
                flash("Saldo insuficiente.", "error")
                return redirect(url_for("withdraw"))

            db.execute(
                """
                INSERT INTO transactions
                (account_id, transaction_type, amount_cents, description)
                VALUES (?, 'withdraw', ?, 'Saque')
                """,
                (account["id"], amount)
            )

        flash("Saque realizado com sucesso!", "success")
        return redirect(url_for("dashboard"))

    return render_page("""
        <h2>Sacar</h2>

        <form method="POST">

            <input type="hidden" name="csrf_token" value="{{ session['csrf_token'] }}">

            <input name="amount" placeholder="Valor do saque" required>

            <button type="submit">Confirmar saque</button>

        </form>

        <a href="{{ url_for('dashboard') }}">Voltar</a>
    """)


# TRANSFERÊNCIA

@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():

    if request.method == "POST":

        if request.form.get("csrf_token") != session.get("csrf_token"):
            flash("Solicitação inválida.", "error")
            return redirect(url_for("transfer"))

        destination_number = request.form.get("account_number", "").strip()
        amount = convert_to_cents(request.form.get("amount", ""))

        if amount is None:
            flash("Digite um valor válido.", "error")
            return redirect(url_for("transfer"))

        db = get_db()
        origin = get_account()

        destination = db.execute(
            """
            SELECT * FROM accounts
            WHERE account_number = ?
            """,
            (destination_number,)
        ).fetchone()

        if not destination:
            flash("Conta de destino não encontrada.", "error")
            return redirect(url_for("transfer"))

        if destination["id"] == origin["id"]:
            flash("Você não pode transferir para sua própria conta.", "error")
            return redirect(url_for("transfer"))

        with db:

            result = db.execute(
                """
                UPDATE accounts
                SET balance_cents = balance_cents - ?
                WHERE id = ? AND balance_cents >= ?
                """,
                (amount, origin["id"], amount)
            )

            if result.rowcount == 0:
                flash("Saldo insuficiente.", "error")
                return redirect(url_for("transfer"))

            db.execute(
                """
                UPDATE accounts
                SET balance_cents = balance_cents + ?
                WHERE id = ?
                """,
                (amount, destination["id"])
            )

            db.execute(
                """
                INSERT INTO transactions
                (account_id, transaction_type, amount_cents, description)
                VALUES (?, 'transfer', ?, ?)
                """,
                (origin["id"], amount, f"Transferência para {destination_number}")
            )

            db.execute(
                """
                INSERT INTO transactions
                (account_id, transaction_type, amount_cents, description)
                VALUES (?, 'received', ?, ?)
                """,
                (destination["id"], amount, f"Transferência recebida de {origin['account_number']}")
            )

        flash("Transferência realizada com sucesso!", "success")
        return redirect(url_for("dashboard"))

    return render_page("""
        <h2>Transferir</h2>

        <form method="POST">

            <input type="hidden" name="csrf_token" value="{{ session['csrf_token'] }}">

            <input name="account_number" placeholder="Número da conta de destino" required>

            <input name="amount" placeholder="Valor da transferência" required>

            <button type="submit">Transferir</button>

        </form>

        <a href="{{ url_for('dashboard') }}">Voltar</a>
    """)


# EXTRATO

@app.route("/history")
@login_required
def history():

    account = get_account()
    db = get_db()

    transactions = db.execute(
        """
        SELECT * FROM transactions
        WHERE account_id = ?
        ORDER BY created_at DESC
        """,
        (account["id"],)
    ).fetchall()

    return render_page("""
        <h2>Extrato bancário</h2>

        {% for transaction in transactions %}

            <div class="transaction">

                <strong>{{ transaction['description'] }}</strong>

                <p>{{ transaction['transaction_type'] }}</p>

                <p>{{ format_money(transaction['amount_cents']) }}</p>

                <small>{{ transaction['created_at'] }}</small>

            </div>

        {% else %}

            <p>Nenhuma movimentação encontrada.</p>

        {% endfor %}

        <a href="{{ url_for('dashboard') }}">Voltar</a>
    """,
        transactions=transactions,
        format_money=format_money
    )


# SAIR DA CONTA

@app.route("/logout", methods=["POST"])
@login_required
@csrf_required
def logout():

    session.clear()

    flash("Você saiu da sua conta.", "success")

    return redirect(url_for("login"))


# INICIALIZAÇÃO

if __name__ == "__main__":

    initialize_database()

    app.run(debug=True)