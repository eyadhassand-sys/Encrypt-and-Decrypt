import hashlib
import html
import hmac
import os
import random
import re
import secrets
import sqlite3
import string
import time
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import streamlit as st


APP_TITLE = "Cipher Tongues Hub"
BASE_DIR = os.path.dirname(__file__)
DB_FILE = os.path.join(BASE_DIR, "encrypt_site.db")
CREATOR_USERNAME = "creator"
CREATOR_BOOT_PASSWORD = "1710"
SYNC_SECONDS = 1
ONLINE_WINDOW_SECONDS = 120
PASSWORD_LENGTH = 5
MAX_TRANSLATE_LENGTH = 5000
MAX_CHAT_LENGTH = 900
BASE_ALPHABET = string.ascii_lowercase + string.ascii_uppercase + string.digits
HEADER_MARK = "¤"
HEX_ALPHABET = "0123456789abcdef"
PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
ACCOUNT_HASH_ROUNDS = 180_000
SYMBOL_POOL = (
    "ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ"
    "αβγδεζηθικλμνξοπρστυφχψω"
    "АБВГДЕЖЗИКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
    "абвгдежзиклмнопрстуфхцчшщъыьэюя"
    "ԱԲԳԴԵԶԷԸԹԺԻԼԽԾԿՀՁՂՃՄՅՆՇՈՉՊՋՌՍՎՏՐՑՒՓՔՕՖ"
    "աբգդեզէընդժիլխծկհձղճմյնշոչպջռսվտրցւփքօֆ"
    "ႠႡႢႣႤႥႦႧႨႩႪႫႬႭႮႯႰႱႲႳႴႵႶႷႸႹ"
    "აბგდევზთიკლმნოპჟრსტუფქღყშჩცძწჭხჯჰ"
)


@dataclass(frozen=True)
class LanguagePack:
    name: str
    lore: str
    accent: str


def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def build_languages() -> Dict[str, LanguagePack]:
    packs = [
        LanguagePack("Future Fook", "Chrome-bright speech for tomorrow's hidden traffic.", "#134074"),
        LanguagePack("Neon Vartha", "A neon market dialect with fast electric rhythm.", "#1d7874"),
        LanguagePack("Solar Khepri", "Sun-forged script with brass heat and star-engine tone.", "#b85c00"),
        LanguagePack("Frost Nyrix", "An iceborn cipher tongue with clipped northern sound.", "#4f6d7a"),
        LanguagePack("Ember Talek", "Furnace-lit language shaped by sparks and hot iron.", "#b23a48"),
        LanguagePack("Lunar Quorin", "A moonline dialect built on pale arcs and quiet motion.", "#5b5f97"),
        LanguagePack("Aether Zol", "A floating signal language designed for cloud-hidden notes.", "#2a6f97"),
        LanguagePack("Mirage Voss", "A shimmering desert language with mirrored cadence.", "#9c6644"),
        LanguagePack("Quantum Rook", "A lab-forged lock language for sharp compact secrets.", "#3d348b"),
        LanguagePack("Pulse Drav", "A heartbeat code that feels metallic and alive.", "#8d0801"),
        LanguagePack("Orbit Kaelis", "A station-born dialect with circular orbital balance.", "#006494"),
        LanguagePack("Velvet Sorn", "A smooth elegant script that hides hard math softly.", "#7f4f24"),
        LanguagePack("Nova Thyra", "A stellar language for bright flashes of meaning.", "#7b2cbf"),
        LanguagePack("Iron Selic", "An industrial forged dialect with strong corners.", "#495057"),
        LanguagePack("Echo Faryn", "A canyon language that returns sound in clean loops.", "#33658a"),
    ]
    return {pack.name: pack for pack in packs}


LANGUAGES = build_languages()
LANGUAGE_NAMES = list(LANGUAGES.keys())


def remember_db_save() -> None:
    st.session_state.last_saved_at = now_text()


def open_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def make_password_hash(password: str, salt_hex: Optional[str] = None) -> Tuple[str, str]:
    salt_hex = salt_hex or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        ACCOUNT_HASH_ROUNDS,
    ).hex()
    return salt_hex, digest


def verify_password(password: str, salt_hex: str, digest_hex: str) -> bool:
    _, expected = make_password_hash(password, salt_hex)
    return hmac.compare_digest(expected, digest_hex)


def init_db() -> None:
    with closing(open_db()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                bio TEXT NOT NULL DEFAULT '',
                joined_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS friend_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                responded_at TEXT,
                FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(receiver_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS friendships (
                user_low INTEGER NOT NULL,
                user_high INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(user_low, user_high),
                FOREIGN KEY(user_low) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(user_high) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(receiver_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        creator = conn.execute(
            "SELECT id FROM users WHERE username = ? COLLATE NOCASE",
            (CREATOR_USERNAME,),
        ).fetchone()
        if creator is None:
            salt, digest = make_password_hash(CREATOR_BOOT_PASSWORD)
            timestamp = now_text()
            conn.execute(
                """
                INSERT INTO users (username, password_salt, password_hash, role, bio, joined_at, last_seen_at)
                VALUES (?, ?, ?, 'creator', ?, ?, ?)
                """,
                (
                    CREATOR_USERNAME,
                    salt,
                    digest,
                    "Creator account for site management. Passwords are stored hashed for safety.",
                    timestamp,
                    timestamp,
                ),
            )
        conn.commit()


def ensure_state() -> None:
    defaults = {
        "logged_in": False,
        "current_user_id": None,
        "current_username": "",
        "current_role": "guest",
        "last_saved_at": "Waiting...",
        "last_touch_epoch": 0.0,
        "encrypt_output": "",
        "encrypt_password_used": "",
        "encrypt_error": "",
        "decrypt_output": "",
        "decrypt_error": "",
        "enc_password": "",
        "dec_password": "",
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def sign_out() -> None:
    st.session_state.logged_in = False
    st.session_state.current_user_id = None
    st.session_state.current_username = ""
    st.session_state.current_role = "guest"


def load_current_user() -> Optional[sqlite3.Row]:
    if not st.session_state.logged_in or not st.session_state.current_user_id:
        return None
    with closing(open_db()) as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (st.session_state.current_user_id,)).fetchone()
    if user is None:
        sign_out()
        return None
    st.session_state.current_username = user["username"]
    st.session_state.current_role = user["role"]
    return user


def touch_user(user_id: int) -> None:
    with closing(open_db()) as conn:
        conn.execute("UPDATE users SET last_seen_at = ? WHERE id = ?", (now_text(), user_id))
        conn.commit()
    remember_db_save()


def maybe_touch_current_user(force: bool = False) -> None:
    if not st.session_state.logged_in or not st.session_state.current_user_id:
        return
    current_time = time.time()
    if force or current_time - float(st.session_state.get("last_touch_epoch", 0.0)) >= 1.0:
        touch_user(int(st.session_state.current_user_id))
        st.session_state.last_touch_epoch = current_time


def create_user(username: str, password: str) -> None:
    username = username.strip()
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("Username must be 3-20 characters using letters, numbers, or _.")
    if len(password) < 4:
        raise ValueError("Account password must be at least 4 characters.")
    with closing(open_db()) as conn:
        existing = conn.execute(
            "SELECT 1 FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()
        if existing:
            raise ValueError("That username already exists.")
        salt, digest = make_password_hash(password)
        timestamp = now_text()
        conn.execute(
            """
            INSERT INTO users (username, password_salt, password_hash, role, bio, joined_at, last_seen_at)
            VALUES (?, ?, ?, 'member', ?, ?, ?)
            """,
            (username, salt, digest, "New member of Cipher Tongues Hub.", timestamp, timestamp),
        )
        conn.commit()
    remember_db_save()


def authenticate_user(username: str, password: str) -> Optional[sqlite3.Row]:
    with closing(open_db()) as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (username.strip(),),
        ).fetchone()
    if user and verify_password(password, user["password_salt"], user["password_hash"]):
        return user
    return None


def login_user(user: sqlite3.Row) -> None:
    st.session_state.logged_in = True
    st.session_state.current_user_id = user["id"]
    st.session_state.current_username = user["username"]
    st.session_state.current_role = user["role"]
    maybe_touch_current_user(force=True)


def update_bio(user_id: int, bio: str) -> None:
    with closing(open_db()) as conn:
        conn.execute("UPDATE users SET bio = ? WHERE id = ?", (bio.strip(), user_id))
        conn.commit()
    remember_db_save()


def change_account_password(user_id: int, old_password: str, new_password: str) -> None:
    if len(new_password) < 4:
        raise ValueError("New password must be at least 4 characters.")
    with closing(open_db()) as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None:
            raise ValueError("User account was not found.")
        if not verify_password(old_password, user["password_salt"], user["password_hash"]):
            raise ValueError("Current password is wrong.")
        salt, digest = make_password_hash(new_password)
        conn.execute(
            "UPDATE users SET password_salt = ?, password_hash = ? WHERE id = ?",
            (salt, digest, user_id),
        )
        conn.commit()
    remember_db_save()


def normalize_pair(user_a: int, user_b: int) -> Tuple[int, int]:
    return (user_a, user_b) if user_a < user_b else (user_b, user_a)


def are_friends(conn: sqlite3.Connection, user_a: int, user_b: int) -> bool:
    low, high = normalize_pair(user_a, user_b)
    row = conn.execute(
        "SELECT 1 FROM friendships WHERE user_low = ? AND user_high = ?",
        (low, high),
    ).fetchone()
    return row is not None


def create_friendship(conn: sqlite3.Connection, user_a: int, user_b: int) -> None:
    low, high = normalize_pair(user_a, user_b)
    conn.execute(
        "INSERT OR IGNORE INTO friendships (user_low, user_high, created_at) VALUES (?, ?, ?)",
        (low, high, now_text()),
    )
    conn.execute(
        """
        UPDATE friend_requests
        SET status = 'accepted', responded_at = ?
        WHERE status = 'pending'
          AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
        """,
        (now_text(), user_a, user_b, user_b, user_a),
    )


def send_friend_request(sender_id: int, receiver_username: str) -> str:
    receiver_username = receiver_username.strip()
    with closing(open_db()) as conn:
        receiver = conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (receiver_username,),
        ).fetchone()
        if receiver is None:
            raise ValueError("That user does not exist.")
        receiver_id = int(receiver["id"])
        if receiver_id == sender_id:
            raise ValueError("You cannot add yourself.")
        if are_friends(conn, sender_id, receiver_id):
            raise ValueError("You are already friends.")

        reverse = conn.execute(
            """
            SELECT id FROM friend_requests
            WHERE sender_id = ? AND receiver_id = ? AND status = 'pending'
            ORDER BY id DESC LIMIT 1
            """,
            (receiver_id, sender_id),
        ).fetchone()
        if reverse is not None:
            create_friendship(conn, sender_id, receiver_id)
            conn.commit()
            remember_db_save()
            return f"You and {receiver['username']} are now friends."

        same = conn.execute(
            """
            SELECT 1 FROM friend_requests
            WHERE sender_id = ? AND receiver_id = ? AND status = 'pending'
            """,
            (sender_id, receiver_id),
        ).fetchone()
        if same is not None:
            raise ValueError("Friend request already sent.")

        conn.execute(
            """
            INSERT INTO friend_requests (sender_id, receiver_id, status, created_at)
            VALUES (?, ?, 'pending', ?)
            """,
            (sender_id, receiver_id, now_text()),
        )
        conn.commit()
    remember_db_save()
    return f"Friend request sent to {receiver['username']}."


def accept_friend_request(request_id: int, receiver_id: int) -> None:
    with closing(open_db()) as conn:
        request = conn.execute(
            """
            SELECT * FROM friend_requests
            WHERE id = ? AND receiver_id = ? AND status = 'pending'
            """,
            (request_id, receiver_id),
        ).fetchone()
        if request is None:
            raise ValueError("Friend request was not found.")
        create_friendship(conn, int(request["sender_id"]), receiver_id)
        conn.commit()
    remember_db_save()


def decline_friend_request(request_id: int, receiver_id: int) -> None:
    with closing(open_db()) as conn:
        conn.execute(
            """
            UPDATE friend_requests
            SET status = 'declined', responded_at = ?
            WHERE id = ? AND receiver_id = ? AND status = 'pending'
            """,
            (now_text(), request_id, receiver_id),
        )
        conn.commit()
    remember_db_save()


def remove_friend(user_id: int, friend_id: int) -> None:
    low, high = normalize_pair(user_id, friend_id)
    with closing(open_db()) as conn:
        conn.execute(
            "DELETE FROM friendships WHERE user_low = ? AND user_high = ?",
            (low, high),
        )
        conn.commit()
    remember_db_save()


def get_received_requests(user_id: int) -> List[sqlite3.Row]:
    with closing(open_db()) as conn:
        return conn.execute(
            """
            SELECT fr.id, fr.created_at, u.username, u.last_seen_at
            FROM friend_requests fr
            JOIN users u ON u.id = fr.sender_id
            WHERE fr.receiver_id = ? AND fr.status = 'pending'
            ORDER BY fr.id DESC
            """,
            (user_id,),
        ).fetchall()


def get_sent_requests(user_id: int) -> List[sqlite3.Row]:
    with closing(open_db()) as conn:
        return conn.execute(
            """
            SELECT fr.id, fr.created_at, u.username, u.last_seen_at
            FROM friend_requests fr
            JOIN users u ON u.id = fr.receiver_id
            WHERE fr.sender_id = ? AND fr.status = 'pending'
            ORDER BY fr.id DESC
            """,
            (user_id,),
        ).fetchall()


def get_friends(user_id: int) -> List[sqlite3.Row]:
    with closing(open_db()) as conn:
        return conn.execute(
            """
            SELECT
                u.id,
                u.username,
                u.role,
                u.bio,
                u.last_seen_at,
                f.created_at AS friends_since
            FROM friendships f
            JOIN users u
                ON u.id = CASE
                    WHEN f.user_low = ? THEN f.user_high
                    ELSE f.user_low
                END
            WHERE f.user_low = ? OR f.user_high = ?
            ORDER BY u.username COLLATE NOCASE
            """,
            (user_id, user_id, user_id),
        ).fetchall()


def get_directory(user_id: int) -> List[sqlite3.Row]:
    with closing(open_db()) as conn:
        return conn.execute(
            """
            SELECT id, username, role, bio, joined_at, last_seen_at
            FROM users
            WHERE id <> ?
            ORDER BY username COLLATE NOCASE
            """,
            (user_id,),
        ).fetchall()


def send_chat_message(sender_id: int, receiver_id: int, body: str) -> None:
    body = body.rstrip()
    if not body.strip():
        raise ValueError("Write a message before sending.")
    if len(body) > MAX_CHAT_LENGTH:
        raise ValueError(f"Messages can be up to {MAX_CHAT_LENGTH} characters.")
    with closing(open_db()) as conn:
        if not are_friends(conn, sender_id, receiver_id):
            raise ValueError("You can only chat with accepted friends.")
        conn.execute(
            """
            INSERT INTO messages (sender_id, receiver_id, body, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (sender_id, receiver_id, body, now_text()),
        )
        conn.commit()
    remember_db_save()


def get_conversation(user_id: int, friend_id: int) -> List[sqlite3.Row]:
    with closing(open_db()) as conn:
        return conn.execute(
            """
            SELECT
                m.id,
                m.body,
                m.created_at,
                m.sender_id,
                m.receiver_id,
                sender.username AS sender_name,
                receiver.username AS receiver_name
            FROM messages m
            JOIN users sender ON sender.id = m.sender_id
            JOIN users receiver ON receiver.id = m.receiver_id
            WHERE (m.sender_id = ? AND m.receiver_id = ?)
               OR (m.sender_id = ? AND m.receiver_id = ?)
            ORDER BY m.id ASC
            """,
            (user_id, friend_id, friend_id, user_id),
        ).fetchall()


def get_recent_messages(limit: int = 250) -> List[sqlite3.Row]:
    with closing(open_db()) as conn:
        return conn.execute(
            """
            SELECT
                m.id,
                m.body,
                m.created_at,
                sender.username AS sender_name,
                receiver.username AS receiver_name
            FROM messages m
            JOIN users sender ON sender.id = m.sender_id
            JOIN users receiver ON receiver.id = m.receiver_id
            ORDER BY m.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def get_all_users() -> List[sqlite3.Row]:
    with closing(open_db()) as conn:
        return conn.execute(
            """
            SELECT id, username, role, bio, joined_at, last_seen_at
            FROM users
            ORDER BY username COLLATE NOCASE
            """
        ).fetchall()


def count_online_users() -> int:
    cutoff = (datetime.now() - timedelta(seconds=ONLINE_WINDOW_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")
    with closing(open_db()) as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS total FROM users WHERE last_seen_at >= ?",
            (cutoff,),
        ).fetchone()
    return int(row["total"]) if row else 0


def get_online_users(limit: int = 12) -> List[sqlite3.Row]:
    cutoff = (datetime.now() - timedelta(seconds=ONLINE_WINDOW_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")
    with closing(open_db()) as conn:
        return conn.execute(
            """
            SELECT username, role, last_seen_at
            FROM users
            WHERE last_seen_at >= ?
            ORDER BY last_seen_at DESC, username COLLATE NOCASE
            LIMIT ?
            """,
            (cutoff, limit),
        ).fetchall()


def is_online(last_seen_at: str) -> bool:
    try:
        seen_at = datetime.strptime(last_seen_at, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False
    return (datetime.now() - seen_at).total_seconds() <= ONLINE_WINDOW_SECONDS


def status_text(last_seen_at: str) -> str:
    if is_online(last_seen_at):
        return "Online"
    try:
        seen_at = datetime.strptime(last_seen_at, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return "Offline"
    delta = datetime.now() - seen_at
    minutes = max(1, int(delta.total_seconds() // 60))
    return f"Seen {minutes} min ago"


def generate_short_password() -> str:
    return "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(PASSWORD_LENGTH))


def normalize_cipher_password(password: str) -> str:
    cleaned = password.strip().upper()
    if not cleaned:
        return ""
    if len(cleaned) > PASSWORD_LENGTH:
        raise ValueError(f"Message password must be at most {PASSWORD_LENGTH} letters or numbers.")
    if not cleaned.isalnum():
        raise ValueError("Message password can only use letters and numbers.")
    return cleaned


def get_language_alphabet(language_name: str) -> str:
    if len(set(SYMBOL_POOL)) < len(BASE_ALPHABET):
        raise ValueError("Symbol pool is too small for the cipher alphabet.")
    pool = list(dict.fromkeys(SYMBOL_POOL))
    rng = random.Random(int(hashlib.sha256(language_name.encode("utf-8")).hexdigest(), 16))
    rng.shuffle(pool)
    return "".join(pool[: len(BASE_ALPHABET)])


def shift_for(password: str, language_name: str, position: int) -> int:
    key = hashlib.sha256(f"{language_name}|{password}".encode("utf-8")).digest()
    block = hmac.new(key, str(position).encode("utf-8"), hashlib.sha256).digest()
    return (block[0] + block[11] + position) % len(BASE_ALPHABET)


def encode_checksum(checksum_hex: str, language_name: str) -> str:
    symbols = get_language_alphabet(language_name)
    return "".join(symbols[HEX_ALPHABET.index(char)] for char in checksum_hex)


def decode_checksum(checksum_text: str, language_name: str) -> str:
    symbols = get_language_alphabet(language_name)
    lookup = {symbols[index]: HEX_ALPHABET[index] for index in range(len(HEX_ALPHABET))}
    try:
        return "".join(lookup[char] for char in checksum_text)
    except KeyError as exc:
        raise ValueError("This text does not match the selected language.") from exc


def calculate_checksum(text: str, password: str, language_name: str) -> str:
    source = f"{language_name}|{password}|{text}".encode("utf-8")
    return hashlib.sha256(source).hexdigest()[:4]


def encrypt_to_language(text: str, password: str, language_name: str) -> str:
    if not text:
        raise ValueError("Enter some text to translate.")
    if len(text) > MAX_TRANSLATE_LENGTH:
        raise ValueError(f"Text can be up to {MAX_TRANSLATE_LENGTH} characters.")
    password = normalize_cipher_password(password)
    if not password:
        password = generate_short_password()

    symbols = get_language_alphabet(language_name)
    output: List[str] = []
    transform_index = 0
    for char in text:
        source_index = BASE_ALPHABET.find(char)
        if source_index == -1:
            output.append(char)
            continue
        shift = shift_for(password, language_name, transform_index)
        cipher_index = (source_index + shift) % len(BASE_ALPHABET)
        output.append(symbols[cipher_index])
        transform_index += 1

    body = "".join(output)
    checksum = calculate_checksum(text, password, language_name)
    return f"{HEADER_MARK}{encode_checksum(checksum, language_name)}{HEADER_MARK}{body}"


def decrypt_from_language(text: str, password: str, language_name: str) -> str:
    password = normalize_cipher_password(password)
    if not password:
        raise ValueError("Enter the same message password used for encryption.")
    if not text.startswith(HEADER_MARK) or len(text) < 6 or text[5] != HEADER_MARK:
        raise ValueError("This message is missing the compact cipher header.")

    checksum_text = text[1:5]
    expected_checksum = decode_checksum(checksum_text, language_name)
    body = text[6:]
    symbols = get_language_alphabet(language_name)
    reverse_lookup = {symbol: index for index, symbol in enumerate(symbols)}

    output: List[str] = []
    transform_index = 0
    for char in body:
        if char not in reverse_lookup:
            output.append(char)
            continue
        cipher_index = reverse_lookup[char]
        shift = shift_for(password, language_name, transform_index)
        source_index = (cipher_index - shift) % len(BASE_ALPHABET)
        output.append(BASE_ALPHABET[source_index])
        transform_index += 1

    plain_text = "".join(output)
    actual_checksum = calculate_checksum(plain_text, password, language_name)
    if actual_checksum != expected_checksum:
        raise ValueError("Wrong password or wrong language for this message.")
    return plain_text


def adaptive_text_height(text: str, minimum: int, maximum: int) -> int:
    lines = max(1, text.count("\n") + 1)
    wrapped = max(0, len(text) // 85)
    return max(minimum, min(maximum, 88 + ((lines + wrapped) * 22)))


def html_text(value: str) -> str:
    return html.escape(value).replace("\n", "<br>")


def inject_styles() -> None:
    st.markdown(
        """
        <style>
        .stApp {
            background:
                radial-gradient(circle at top left, rgba(255, 212, 140, 0.26) 0%, transparent 24%),
                radial-gradient(circle at top right, rgba(131, 197, 255, 0.26) 0%, transparent 24%),
                linear-gradient(180deg, #fffaf2 0%, #eef7ff 50%, #f2fff6 100%);
        }
        .block-container {
            max-width: 1220px;
            padding-top: 1.7rem;
            padding-bottom: 2rem;
        }
        h1, h2, h3, h4 {
            color: #13395b !important;
        }
        p, label, .stMarkdown, div[data-testid="stMarkdownContainer"] {
            color: #17324d !important;
        }
        .hero-card {
            background: linear-gradient(135deg, #0b2545 0%, #134074 52%, #2a6f97 100%);
            border-radius: 28px;
            padding: 28px 30px;
            color: #f8fbff;
            box-shadow: 0 24px 52px rgba(11, 37, 69, 0.20);
            margin-bottom: 16px;
        }
        .hero-card h1, .hero-card p {
            color: #f8fbff !important;
        }
        .hero-eyebrow {
            letter-spacing: 0.18em;
            text-transform: uppercase;
            font-size: 0.78rem;
            font-weight: 800;
            color: #ffd27d !important;
        }
        .glass-card {
            background: rgba(255, 255, 255, 0.84);
            border: 1px solid rgba(20, 74, 117, 0.14);
            border-radius: 22px;
            padding: 18px;
            box-shadow: 0 14px 30px rgba(16, 58, 92, 0.08);
            margin-bottom: 14px;
        }
        .glass-card h3, .glass-card p {
            margin-top: 0;
        }
        .status-chip {
            display: inline-block;
            padding: 6px 11px;
            border-radius: 999px;
            font-size: 0.85rem;
            font-weight: 700;
            margin-right: 6px;
            margin-bottom: 6px;
        }
        .chip-online {
            background: #dcfce7;
            color: #166534 !important;
        }
        .chip-offline {
            background: #e2e8f0;
            color: #334155 !important;
        }
        .chat-bubble-me {
            background: linear-gradient(180deg, #dbeafe 0%, #eff6ff 100%);
            border: 1px solid #93c5fd;
            border-radius: 18px;
            padding: 12px 14px;
            margin-bottom: 10px;
        }
        .chat-bubble-other {
            background: linear-gradient(180deg, #fef3c7 0%, #fffbeb 100%);
            border: 1px solid #fcd34d;
            border-radius: 18px;
            padding: 12px 14px;
            margin-bottom: 10px;
        }
        .cipher-sample {
            font-size: 1.06rem;
            line-height: 1.55;
            word-break: break-word;
        }
        .small-note {
            color: #31506b !important;
            font-size: 0.95rem;
        }
        .stTextArea textarea,
        .stTextInput input,
        .stSelectbox div[data-baseweb="select"] > div,
        .stTextArea textarea::placeholder,
        .stTextInput input::placeholder {
            background: #fcfeff !important;
            color: #102a43 !important;
        }
        .stTextArea textarea,
        .stTextInput input,
        .stSelectbox div[data-baseweb="select"] > div {
            border: 1px solid #9dbdd9 !important;
        }
        div[data-testid="stMetricValue"] {
            color: #13395b !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_hero() -> None:
    st.markdown(
        f"""
        <div class="hero-card">
            <div class="hero-eyebrow">Compact Cipher + Social Site</div>
            <h1>{APP_TITLE}</h1>
            <p>
                Translate text into compact fictional languages, keep symbols like = unchanged,
                generate short message passwords, and chat with accepted friends on a database-backed site.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_sync_status_impl() -> None:
    if st.session_state.get("logged_in") and st.session_state.get("current_user_id"):
        maybe_touch_current_user(force=True)
    st.caption(f"Database sync active | Last write: {st.session_state.get('last_saved_at', 'Waiting...')}")


if hasattr(st, "fragment"):
    try:
        render_sync_status = st.fragment(run_every=f"{SYNC_SECONDS}s")(_render_sync_status_impl)
    except TypeError:
        render_sync_status = _render_sync_status_impl
else:
    render_sync_status = _render_sync_status_impl


def render_sidebar(current_user: Optional[sqlite3.Row]) -> None:
    st.sidebar.header("Site Status")
    st.sidebar.metric("Registered users", len(get_all_users()))
    st.sidebar.metric("Online now", count_online_users())
    if current_user is not None:
        st.sidebar.success(f"Signed in as {current_user['username']}")
        st.sidebar.caption(f"Role: {current_user['role']}")
        if st.sidebar.button("Log Out", use_container_width=True):
            sign_out()
            st.rerun()
    else:
        st.sidebar.info("Sign in to use friends and chat.")

    online_users = get_online_users()
    if online_users:
        st.sidebar.markdown("**Online people**")
        for person in online_users:
            st.sidebar.write(f"- {person['username']} ({person['role']})")


def relationship_sets(user_id: int) -> Tuple[set, set, set]:
    friend_ids = {int(row["id"]) for row in get_friends(user_id)}
    sent_ids = set()
    received_ids = set()
    with closing(open_db()) as conn:
        for row in conn.execute(
            "SELECT receiver_id FROM friend_requests WHERE sender_id = ? AND status = 'pending'",
            (user_id,),
        ).fetchall():
            sent_ids.add(int(row["receiver_id"]))
        for row in conn.execute(
            "SELECT sender_id FROM friend_requests WHERE receiver_id = ? AND status = 'pending'",
            (user_id,),
        ).fetchall():
            received_ids.add(int(row["sender_id"]))
    return friend_ids, sent_ids, received_ids


def render_language_card(pack: LanguagePack) -> None:
    sample = encrypt_to_language("Hello = Hello 123", "A1B2C", pack.name)
    st.markdown(
        f"""
        <div class="glass-card" style="border-top: 5px solid {pack.accent};">
            <h3>{pack.name}</h3>
            <p>{pack.lore}</p>
            <div class="cipher-sample">{sample}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_translator_tab() -> None:
    st.subheader("Compact Language Translator")
    st.markdown(
        '<p class="small-note">Letters and numbers are translated into the chosen language. Symbols like = stay unchanged.</p>',
        unsafe_allow_html=True,
    )
    left, right = st.columns(2)

    with left:
        st.markdown("### Encrypt / Translate")
        encrypt_language = st.selectbox("Language", LANGUAGE_NAMES, key="encrypt_language_choice")
        if st.button("Generate 5-char Message Password", key="generate_cipher_password", use_container_width=True):
            st.session_state.enc_password = generate_short_password()
        encrypt_password = st.text_input(
            "Message Password",
            key="enc_password",
            max_chars=PASSWORD_LENGTH,
            help="If left empty, the app will generate one automatically.",
        )
        encrypt_text = st.text_area(
            "Text to translate",
            key="encrypt_source_text",
            height=180,
            placeholder="Write text here. Example: x = y + 7",
        )
        if st.button("Translate Into Language", key="encrypt_action", use_container_width=True):
            try:
                chosen_password = normalize_cipher_password(encrypt_password)
                if not chosen_password:
                    chosen_password = generate_short_password()
                    st.session_state.enc_password = chosen_password
                st.session_state.encrypt_output = encrypt_to_language(encrypt_text, chosen_password, encrypt_language)
                st.session_state.encrypt_password_used = chosen_password
                st.session_state.encrypt_error = ""
            except ValueError as exc:
                st.session_state.encrypt_output = ""
                st.session_state.encrypt_error = str(exc)

        if st.session_state.encrypt_error:
            st.error(st.session_state.encrypt_error)
        if st.session_state.encrypt_output:
            st.success(f"Saved compact output in {encrypt_language}.")
            st.info(f"Message password: {st.session_state.encrypt_password_used}")
            st.text_area(
                "Translated encrypted text",
                value=st.session_state.encrypt_output,
                height=adaptive_text_height(st.session_state.encrypt_output, 150, 320),
            )

    with right:
        st.markdown("### Decrypt / Translate Back")
        decrypt_language = st.selectbox("Language", LANGUAGE_NAMES, key="decrypt_language_choice")
        decrypt_password = st.text_input(
            "Message Password",
            key="dec_password",
            max_chars=PASSWORD_LENGTH,
        )
        decrypt_text = st.text_area(
            "Encrypted text",
            key="decrypt_source_text",
            height=180,
            placeholder="Paste translated text here...",
        )
        if st.button("Translate Back", key="decrypt_action", use_container_width=True):
            try:
                st.session_state.decrypt_output = decrypt_from_language(decrypt_text, decrypt_password, decrypt_language)
                st.session_state.decrypt_error = ""
            except ValueError as exc:
                st.session_state.decrypt_output = ""
                st.session_state.decrypt_error = str(exc)

        if st.session_state.decrypt_error:
            st.error(st.session_state.decrypt_error)
        if st.session_state.decrypt_output:
            st.success("Text restored successfully.")
            st.text_area(
                "Decrypted text",
                value=st.session_state.decrypt_output,
                height=adaptive_text_height(st.session_state.decrypt_output, 140, 260),
            )


def render_account_tab() -> None:
    st.subheader("Accounts")
    st.markdown(
        '<p class="small-note">Create an account to add friends and chat. The creator account is explicit, and user passwords are stored hashed.</p>',
        unsafe_allow_html=True,
    )
    st.info(f"Creator login: username `{CREATOR_USERNAME}` | password `{CREATOR_BOOT_PASSWORD}`. Change it after login.")
    login_col, signup_col = st.columns(2)

    with login_col:
        st.markdown("### Log In")
        with st.form("login_form"):
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            submitted = st.form_submit_button("Log In", use_container_width=True)
        if submitted:
            user = authenticate_user(username, password)
            if user is None:
                st.error("Wrong username or password.")
            else:
                login_user(user)
                st.success(f"Welcome back, {user['username']}.")
                st.rerun()

    with signup_col:
        st.markdown("### Create Account")
        with st.form("signup_form"):
            username = st.text_input("New Username", key="signup_username")
            password = st.text_input("New Password", type="password", key="signup_password")
            submitted = st.form_submit_button("Create Account", use_container_width=True)
        if submitted:
            try:
                create_user(username, password)
                user = authenticate_user(username, password)
                if user is not None:
                    login_user(user)
                st.success("Account created.")
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))


def render_friends_tab(current_user: sqlite3.Row) -> None:
    st.subheader("Friends and Online People")
    friend_ids, sent_ids, received_ids = relationship_sets(int(current_user["id"]))
    users = get_directory(int(current_user["id"]))
    friends = get_friends(int(current_user["id"]))
    received = get_received_requests(int(current_user["id"]))
    sent = get_sent_requests(int(current_user["id"]))

    metrics = st.columns(3)
    metrics[0].metric("Friends", len(friends))
    metrics[1].metric("Received Requests", len(received))
    metrics[2].metric("Sent Requests", len(sent))

    if received:
        st.markdown("### Requests Waiting For You")
        for request in received:
            cols = st.columns([2.4, 1, 1])
            cols[0].markdown(
                f"**{request['username']}**  \n{status_text(request['last_seen_at'])}  \nSent: {request['created_at']}"
            )
            if cols[1].button("Accept", key=f"accept_request_{request['id']}", use_container_width=True):
                accept_friend_request(int(request["id"]), int(current_user["id"]))
                st.rerun()
            if cols[2].button("Decline", key=f"decline_request_{request['id']}", use_container_width=True):
                decline_friend_request(int(request["id"]), int(current_user["id"]))
                st.rerun()

    if sent:
        st.markdown("### Requests You Sent")
        for request in sent:
            st.markdown(f"- **{request['username']}** | {status_text(request['last_seen_at'])}")

    st.markdown("### People Directory")
    search_text = st.text_input("Search people", key="directory_search")
    for user in users:
        username = user["username"]
        if search_text.strip() and search_text.strip().lower() not in username.lower():
            continue
        cols = st.columns([2.4, 1.2, 1])
        cols[0].markdown(f"**{username}** ({user['role']})")
        cols[0].caption(user["bio"].replace("\n", " "))
        cols[0].caption(status_text(user["last_seen_at"]))
        if int(user["id"]) in friend_ids:
            if cols[1].button("Remove Friend", key=f"remove_friend_{user['id']}", use_container_width=True):
                remove_friend(int(current_user["id"]), int(user["id"]))
                st.rerun()
        elif int(user["id"]) in sent_ids:
            cols[1].info("Request sent")
        elif int(user["id"]) in received_ids:
            cols[1].warning("They requested you")
        else:
            if cols[1].button("Add Friend", key=f"add_friend_{user['id']}", use_container_width=True):
                try:
                    message = send_friend_request(int(current_user["id"]), username)
                    st.success(message)
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))

    if friends:
        st.markdown("### Your Friends")
        for friend in friends:
            state_class = "chip-online" if is_online(friend["last_seen_at"]) else "chip-offline"
            state_text = status_text(friend["last_seen_at"])
            safe_bio = html_text(friend["bio"])
            st.markdown(
                f"""
                <div class="glass-card">
                    <h3>{friend['username']}</h3>
                    <span class="status-chip {state_class}">{state_text}</span>
                    <p>{safe_bio}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.info("No friends yet. Send a request to start chatting.")


def render_chat_tab(current_user: sqlite3.Row) -> None:
    st.subheader("Friend Chat")
    st.markdown(
        '<p class="small-note">Chat is available only after the friendship is accepted. You can paste translated cipher text here if you want secret-looking messages.</p>',
        unsafe_allow_html=True,
    )
    friends = get_friends(int(current_user["id"]))
    if not friends:
        st.info("Add and accept a friend first to unlock chat.")
        return

    friend_lookup = {friend["username"]: friend for friend in friends}
    chosen_friend_name = st.selectbox("Choose a friend", list(friend_lookup.keys()), key="chat_friend_choice")
    chosen_friend = friend_lookup[chosen_friend_name]
    conversation = get_conversation(int(current_user["id"]), int(chosen_friend["id"]))

    st.markdown(
        f"**Chat with {chosen_friend['username']}**  \n{status_text(chosen_friend['last_seen_at'])}"
    )
    for message in conversation:
        bubble_class = "chat-bubble-me" if int(message["sender_id"]) == int(current_user["id"]) else "chat-bubble-other"
        safe_body = html_text(message["body"])
        st.markdown(
            f"""
            <div class="{bubble_class}">
                <strong>{message['sender_name']}</strong><br>
                {safe_body}<br>
                <span class="small-note">{message['created_at']}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with st.form("chat_form", clear_on_submit=True):
        body = st.text_area(
            "Write a message",
            height=120,
            placeholder="Type here. Symbols like = stay exactly as you write them.",
        )
        submitted = st.form_submit_button("Send Message", use_container_width=True)
    if submitted:
        try:
            send_chat_message(int(current_user["id"]), int(chosen_friend["id"]), body)
            st.success("Message sent.")
            st.rerun()
        except ValueError as exc:
            st.error(str(exc))


def render_profile_tab(current_user: sqlite3.Row) -> None:
    st.subheader("Profile")
    top = st.columns(3)
    top[0].metric("Username", current_user["username"])
    top[1].metric("Role", current_user["role"])
    top[2].metric("Joined", current_user["joined_at"].split(" ")[0])

    with st.form("profile_form"):
        bio = st.text_area("Bio", value=current_user["bio"], height=140)
        saved = st.form_submit_button("Save Bio", use_container_width=True)
    if saved:
        update_bio(int(current_user["id"]), bio)
        st.success("Bio updated.")
        st.rerun()

    st.markdown("### Change Account Password")
    with st.form("password_change_form"):
        old_password = st.text_input("Current Password", type="password")
        new_password = st.text_input("New Password", type="password")
        submitted = st.form_submit_button("Change Password", use_container_width=True)
    if submitted:
        try:
            change_account_password(int(current_user["id"]), old_password, new_password)
            st.success("Account password changed.")
        except ValueError as exc:
            st.error(str(exc))


def render_creator_tab(current_user: sqlite3.Row) -> None:
    if current_user["role"] != "creator":
        st.info("Creator tools are only available to the creator account.")
        return

    st.subheader("Creator Dashboard")
    st.warning("Creator tools can review site activity. User account passwords are hashed and are never shown.")
    users = get_all_users()
    messages = get_recent_messages()

    metrics = st.columns(3)
    metrics[0].metric("Users", len(users))
    metrics[1].metric("Recent Messages", len(messages))
    metrics[2].metric("Online Now", count_online_users())

    st.markdown("### Members")
    for user in users:
        st.markdown(
            f"- **{user['username']}** ({user['role']}) | {status_text(user['last_seen_at'])} | joined {user['joined_at']}"
        )

    st.markdown("### Recent Chats")
    if not messages:
        st.info("No chat messages yet.")
    else:
        for message in messages:
            safe_body = html_text(message["body"])
            st.markdown(
                f"""
                <div class="glass-card">
                    <strong>{message['sender_name']}</strong> to <strong>{message['receiver_name']}</strong><br>
                    {safe_body}<br>
                    <span class="small-note">{message['created_at']}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )


def render_gallery_tab() -> None:
    st.subheader("Language Gallery")
    st.markdown(
        '<p class="small-note">These languages stay compact because the cipher changes characters without exploding the text into a tall block.</p>',
        unsafe_allow_html=True,
    )
    packs = list(LANGUAGES.values())
    for start in range(0, len(packs), 3):
        columns = st.columns(3)
        for column, pack in zip(columns, packs[start:start + 3]):
            with column:
                render_language_card(pack)


def render_about_tab() -> None:
    st.subheader("About This Build")
    st.markdown(
        """
        <div class="glass-card">
            <p><strong>Compact output:</strong> the app keeps formulas like <code>x = y + 1</code> readable because symbols are preserved.</p>
            <p><strong>Message passwords:</strong> translation passwords are short 5-character codes for quick sharing.</p>
            <p><strong>Database:</strong> account data, friendships, and chat messages are written into SQLite so reloads and sleep do not erase saved actions.</p>
            <p><strong>Friends first:</strong> private chat opens only after a request is accepted.</p>
            <p><strong>Creator safety:</strong> the creator can manage the site, but user account passwords are stored hashed and are not exposed.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, page_icon="C", layout="wide")
    init_db()
    ensure_state()
    inject_styles()

    current_user = load_current_user()
    maybe_touch_current_user()

    render_sidebar(current_user)
    render_hero()
    render_sync_status()

    metrics = st.columns(3)
    metrics[0].metric("Languages", len(LANGUAGES))
    metrics[1].metric("Password Length", PASSWORD_LENGTH)
    metrics[2].metric("Online Users", count_online_users())

    if current_user is None:
        cipher_tab, account_tab, gallery_tab, about_tab = st.tabs(
            ["Translator", "Account", "Language Gallery", "About"]
        )
        with cipher_tab:
            render_translator_tab()
        with account_tab:
            render_account_tab()
        with gallery_tab:
            render_gallery_tab()
        with about_tab:
            render_about_tab()
        return

    tab_names = ["Translator", "Friends", "Chat", "Profile", "Language Gallery", "About"]
    if current_user["role"] == "creator":
        tab_names.insert(4, "Creator")
    tabs = st.tabs(tab_names)

    tab_map = dict(zip(tab_names, tabs))
    with tab_map["Translator"]:
        render_translator_tab()
    with tab_map["Friends"]:
        render_friends_tab(current_user)
    with tab_map["Chat"]:
        render_chat_tab(current_user)
    with tab_map["Profile"]:
        render_profile_tab(current_user)
    if "Creator" in tab_map:
        with tab_map["Creator"]:
            render_creator_tab(current_user)
    with tab_map["Language Gallery"]:
        render_gallery_tab()
    with tab_map["About"]:
        render_about_tab()


if __name__ == "__main__":
    main()
