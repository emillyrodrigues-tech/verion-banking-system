import sqlite3
import os

DATABASE = os.environ.get("DATABASE_PATH", "verion.db")


def get_connection():
    """Cria e retorna uma conexão com o banco de dados."""
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def initialize_database():
    """Cria as tabelas necessárias para o sistema."""

    connection = get_connection()

    try:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                account_number TEXT NOT NULL UNIQUE,
                balance_cents INTEGER NOT NULL DEFAULT 0
                    CHECK (balance_cents >= 0),

                FOREIGN KEY (user_id)
                    REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL,
                transaction_type TEXT NOT NULL,
                amount_cents INTEGER NOT NULL
                    CHECK (amount_cents > 0),
                description TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (account_id)
                    REFERENCES accounts(id)
            );
        """)

        connection.commit()

    finally:
        connection.close()