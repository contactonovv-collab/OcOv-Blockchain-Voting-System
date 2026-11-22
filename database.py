
import sqlite3

DATABASE_NAME = "voting.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    connection = get_connection()
    cursor = connection.cursor()

    # Users: students and administrators
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            roll_number TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            email_verified INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Pending registrations awaiting email verification
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pending_registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            roll_number TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            otp_hash TEXT NOT NULL,
            otp_expiry TEXT NOT NULL,
            attempts INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Elections
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS elections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            start_time TEXT,
            end_time TEXT,
            status TEXT NOT NULL DEFAULT 'draft',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Update existing elections table if necessary
    election_columns = [
        row["name"] for row in connection.execute(
            "PRAGMA table_info(elections)"
        ).fetchall()
    ]

    required_columns = {
        "description": "TEXT",
        "start_time": "TEXT",
        "end_time": "TEXT",
        "results_declared": "INTEGER NOT NULL DEFAULT 0",
        "thumbnail": "TEXT",
        "category": "TEXT NOT NULL DEFAULT 'Other'",
    }

    for column, data_type in required_columns.items():
        if column not in election_columns:
            cursor.execute(
                f"ALTER TABLE elections ADD COLUMN {column} {data_type}"
            )

    # Election categories managed by administrators
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS election_categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Add image support to existing category table if needed
    category_columns = [
        row["name"] for row in connection.execute(
            "PRAGMA table_info(election_categories)"
        ).fetchall()
    ]

    if "image" not in category_columns:
        cursor.execute(
            "ALTER TABLE election_categories ADD COLUMN image TEXT"
        )
    # Insert default categories if they don't already exist
    default_categories = [
        ("Student Council", "Student council elections"),
        ("Class Representative", "Class representative elections"),
        ("Sports", "Sports-related elections"),
        ("Cultural", "Cultural committee elections"),
        ("Department", "Department-level elections"),
        ("Other", "Other college elections"),
    ]

    for name, description in default_categories:
        cursor.execute("""
            INSERT OR IGNORE INTO election_categories (name, description)
            VALUES (?, ?)
        """, (name, description))

    # Candidates belonging to specific elections
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            election_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            party TEXT,
            description TEXT,
            FOREIGN KEY (election_id) REFERENCES elections(id)
        )
    """)

    # Update existing candidates table if necessary
    candidate_columns = [
        row["name"] for row in connection.execute(
            "PRAGMA table_info(candidates)"
        ).fetchall()
    ]

    if "election_id" not in candidate_columns:
        cursor.execute(
            "ALTER TABLE candidates ADD COLUMN election_id INTEGER"
        )

    # Eligible voters for each election
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS election_eligibility (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            election_id INTEGER NOT NULL,
            voter_id INTEGER NOT NULL,
            has_voted INTEGER DEFAULT 0,
            UNIQUE (election_id, voter_id),
            FOREIGN KEY (election_id) REFERENCES elections(id),
            FOREIGN KEY (voter_id) REFERENCES users(id)
        )
    """)

    # Ballots: no direct voter identity stored
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ballots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            election_id INTEGER NOT NULL,
            candidate_id INTEGER NOT NULL,
            ballot_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (election_id) REFERENCES elections(id),
            FOREIGN KEY (candidate_id) REFERENCES candidates(id)
        )
    """)

    # Voter participation records: separate from ballots
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS voting_receipts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            election_id INTEGER NOT NULL,
            voter_id INTEGER NOT NULL,
            voted_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (election_id, voter_id),
            FOREIGN KEY (election_id) REFERENCES elections(id),
            FOREIGN KEY (voter_id) REFERENCES users(id)
        )
    """)

    # Blockchain storage
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            block_index INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            data TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            block_hash TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()

    print("OcOv database structure initialized successfully!")


if __name__ == "__main__":
    initialize_database()
