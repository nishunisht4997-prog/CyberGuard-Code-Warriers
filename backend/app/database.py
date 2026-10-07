import os

from dotenv import load_dotenv
from sqlalchemy import create_engine, URL
from sqlalchemy.orm import sessionmaker

load_dotenv()

DB_USER = os.getenv("DB_USER", "3jEjkiBaLbwsQLn.root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "4UryLZ8cIO0WaiMY")
DB_HOST = os.getenv("DB_HOST", "gateway01.ap-northeast-1.prod.aws.tidbcloud.com")
DB_PORT = os.getenv("DB_PORT", "4000")
DB_NAME = os.getenv("DB_NAME", "test")

DB_STATUS = "SQLITE_DEFAULT"
DB_ERROR = None

if DB_USER and DB_PASSWORD and DB_HOST:
    try:
        mysql_url = URL.create(
            drivername="mysql+pymysql",
            username=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=int(DB_PORT),
            database=DB_NAME,
        )
        conn_args = {"connect_timeout": 12}
        if "tidbcloud" in DB_HOST.lower() or "aivencloud" in DB_HOST.lower() or os.getenv("DB_SSL", "").lower() == "true":
            conn_args["ssl"] = {"ssl_mode": "REQUIRED"}
        test_engine = create_engine(mysql_url, pool_pre_ping=True, connect_args=conn_args)
        with test_engine.connect() as conn:
            pass
        engine = test_engine
        DB_STATUS = f"CONNECTED_MYSQL ({DB_HOST})"
        print(f"[*] Successfully connected to MySQL at {DB_HOST}")
    except Exception as e:
        DB_STATUS = "MYSQL_FAILED_FALLBACK_SQLITE"
        DB_ERROR = str(e)
        print(f"[!] MySQL connection failed ({e}). Falling back to local SQLite database.")

if engine is None:
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sqlite_db_path = os.path.join(backend_dir, "cyberguard.db")
    engine = create_engine(
        f"sqlite:///{sqlite_db_path}",
        connect_args={"check_same_thread": False}
    )
    print(f"[*] Using SQLite database: {sqlite_db_path}")

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


def init_db():
    from sqlalchemy import text
    try:
        is_sqlite = "sqlite" in str(engine.url)
        auto_inc = "INTEGER PRIMARY KEY AUTOINCREMENT" if is_sqlite else "INT AUTO_INCREMENT PRIMARY KEY"
        int_type = "INTEGER" if is_sqlite else "INT"
        bool_type = "INTEGER DEFAULT 0" if is_sqlite else "TINYINT(1) DEFAULT 0"

        with engine.begin() as conn:
            conn.execute(text(f"""
                CREATE TABLE IF NOT EXISTS users (
                    id {auto_inc},
                    name VARCHAR(100) NOT NULL,
                    email VARCHAR(150) NOT NULL,
                    role VARCHAR(50) DEFAULT 'analyst',
                    organisation VARCHAR(150) DEFAULT 'CYBERGUARD-X SOC',
                    department VARCHAR(100) DEFAULT 'Threat Intelligence',
                    is_active {bool_type.replace('DEFAULT 0', 'DEFAULT 1')},
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))

            conn.execute(text(f"""
                CREATE TABLE IF NOT EXISTS threat_events (
                    id {auto_inc},
                    event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source VARCHAR(50) NOT NULL,
                    threat_type VARCHAR(100) NOT NULL,
                    risk_score {int_type} NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    status VARCHAR(50) DEFAULT 'OPEN',
                    summary TEXT
                )
            """))

            conn.execute(text(f"""
                CREATE TABLE IF NOT EXISTS message_analysis (
                    id {auto_inc},
                    event_id {int_type} NOT NULL,
                    sender VARCHAR(255),
                    subject VARCHAR(255),
                    message TEXT,
                    message_text TEXT,
                    urgency_score {int_type} DEFAULT 0,
                    credential_request {bool_type},
                    impersonation_score {int_type} DEFAULT 0,
                    suspicious_keywords TEXT,
                    risk_score {int_type},
                    detected_indicators TEXT,
                    analysis_result VARCHAR(100)
                )
            """))

            conn.execute(text(f"""
                CREATE TABLE IF NOT EXISTS url_analysis (
                    id {auto_inc},
                    event_id {int_type} NOT NULL,
                    url TEXT NOT NULL,
                    domain VARCHAR(255),
                    ssl_valid {bool_type},
                    redirect_count {int_type} DEFAULT 0,
                    domain_similarity_score {int_type} DEFAULT 0,
                    url_risk_score {int_type} DEFAULT 0,
                    suspicious_features TEXT,
                    ip_address VARCHAR(100),
                    risk_score {int_type},
                    detected_indicators TEXT,
                    analysis_result VARCHAR(100)
                )
            """))

            conn.execute(text(f"""
                CREATE TABLE IF NOT EXISTS login_events (
                    id {auto_inc},
                    user_id {int_type},
                    event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address VARCHAR(45),
                    location VARCHAR(100),
                    device VARCHAR(150),
                    login_status VARCHAR(30),
                    failed_attempts {int_type} DEFAULT 0,
                    is_new_device {bool_type},
                    is_unusual_location {bool_type},
                    anomaly_score {int_type} DEFAULT 0,
                    user_agent VARCHAR(255),
                    status VARCHAR(20),
                    risk_score {int_type},
                    failure_reason VARCHAR(255)
                )
            """))

            conn.execute(text(f"""
                CREATE TABLE IF NOT EXISTS media_analysis (
                    id {auto_inc},
                    event_id {int_type} NOT NULL,
                    file_name VARCHAR(255),
                    file_type VARCHAR(50),
                    authenticity_score {int_type},
                    manipulation_score {int_type},
                    model_confidence {int_type},
                    detected_indicators TEXT,
                    analysis_result VARCHAR(100)
                )
            """))

            conn.execute(text(f"""
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    id {auto_inc},
                    event_id {int_type} NOT NULL,
                    indicator_type VARCHAR(100),
                    indicator VARCHAR(255),
                    severity VARCHAR(20),
                    description TEXT
                )
            """))

            conn.execute(text(f"""
                CREATE TABLE IF NOT EXISTS response_actions (
                    id {auto_inc},
                    event_id {int_type} NOT NULL,
                    recommended_action VARCHAR(255) NOT NULL,
                    action_status VARCHAR(50) DEFAULT 'RECOMMENDED',
                    action_reason TEXT
                )
            """))

            conn.execute(text(f"""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id {auto_inc},
                    user_id {int_type},
                    action VARCHAR(255) NOT NULL,
                    result VARCHAR(100),
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))

        print("[*] Database tables verified & initialized successfully.")
    except Exception as e:
        print(f"[!] Database init notice: {e}")

# Run schema check on startup
init_db()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()