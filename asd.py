import requests
import re
import time
import hashlib
import html
from bs4 import BeautifulSoup
from flask import Flask, Response
import threading
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters
)
import asyncio
import os
import logging
import pycountry
from datetime import datetime
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("otp-http-bot")

# -------------------- CONFIG --------------------
LOGIN_URL = os.getenv("LOGIN_URL")
XHR_URL = os.getenv("XHR_URL")
USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")
BOT_TOKEN = os.getenv("BOT_TOKEN")
# ADMIN_ID must be numeric Telegram user id of admin
ADMIN_ID = int(os.getenv("ADMIN_ID"))

DEVELOPER_ID = os.getenv("DEVELOPER_ID", "@hiden_25")
CHANNEL_LINK = os.getenv("CHANNEL_LINK", "https://t.me/freeotpss")

# Poll interval (seconds)
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "1.2"))

# Persistence files
CHAT_IDS_FILE = "chat_ids.json"
MAPPING_FILE = "number_mapping.json"
OTP_LOG_FILE = "otp_logs.txt"

# Flask port
PORT = int(os.getenv("PORT", "8080"))

# -------------------- HELPERS & STATE --------------------
EXTRA_CODES = {"Kosovo": "XK"}  # special cases

def country_to_flag_by_name(country_name: str) -> str:
    code = EXTRA_CODES.get(country_name)
    if not code:
        try:
            country = pycountry.countries.lookup(country_name)
            code = country.alpha_2
        except Exception:
            return ""
    return "".join(chr(127397 + ord(c)) for c in code.upper())

def country_to_flag(code: str) -> str:
    if not code or len(code) != 2:
        return ""
    return "".join(chr(127397 + ord(c)) for c in code.upper())

def normalize_number(num: str) -> str:
    if not num:
        return ""
    return re.sub(r"\D", "", num)

def last_n_digits(num: str, n: int = 10) -> str:
    d = normalize_number(num)
    return d[-n:] if len(d) >= n else d

def mask_number(number: str) -> str:
    d = normalize_number(number)
    if len(d) <= 7:
        return number
    return f"{d[:4]}{'*'*(len(d)-7)}{d[-3:]}"

# Files & persistence locks
chat_lock = threading.Lock()
map_lock = threading.Lock()

def load_chat_ids():
    try:
        with open(CHAT_IDS_FILE, "r") as f:
            return set(json.load(f))
    except Exception:
        return set()

def save_chat_ids(chat_ids):
    try:
        with chat_lock:
            with open(CHAT_IDS_FILE, "w") as f:
                json.dump(list(chat_ids), f)
    except Exception as e:
        logger.exception("Failed to save chat ids: %s", e)

def load_mapping():
    try:
        with open(MAPPING_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}  # normalized_number -> user_id (int)

def save_mapping(mapping):
    try:
        with map_lock:
            with open(MAPPING_FILE, "w") as f:
                json.dump(mapping, f)
    except Exception as e:
        logger.exception("Failed to save mapping: %s", e)

# runtime state
CHAT_IDS = load_chat_ids()        # set of chat id strings
NUMBER_TO_USER = load_mapping()   # dict normalized_number -> int(user_id)
seen = set()                      # in-memory seen hashes
session = requests.Session()
otp_count = 0
last_otp_time = "N/A"
tg_app = None                     # will be set to Application instance
pending_files = {}                # admin_id -> file_path (for /setnumber)

# -------------------- OTP extraction --------------------
def extract_otp_from_text(message: str) -> str | None:
    if not message:
        return None
    # 1) keyword around digits
    m = re.search(r"(?:otp|code|pin|password)[^\d]{0,10}(\d[\d\-\s]{3,8}\d)", message, re.I)
    if m:
        return re.sub(r"\D", "", m.group(1))
    # 2) reverse pattern "123456 is your code"
    m = re.search(r"(\d[\d\-\s]{3,8}\d)[^\w]{0,10}(?:otp|code|pin|password)", message, re.I)
    if m:
        return re.sub(r"\D", "", m.group(1))
    # 3) any 4-8 digit number not year
    candidates = re.findall(r"\b\d{4,8}\b", message)
    for cand in candidates:
        if 1900 <= int(cand) <= 2099:
            continue
        return cand
    return None

# -------------------- TELEGRAM SENDING UTIL (async) --------------------
async def send_message_async(chat_id, text, reply_markup=None):
    # use tg_app.bot to send
    try:
        await tg_app.bot.send_message(chat_id=chat_id, text=text, parse_mode="HTML", reply_markup=reply_markup, disable_web_page_preview=True)
        return True
    except Exception as e:
        logger.exception("Failed to send async message to %s: %s", chat_id, e)
        return False

def send_message_sync(chat_id, text):
    # fallback synchronous HTTP API
    try:
        payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
        r = requests.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", data=payload, timeout=10)
        if r.status_code == 200:
            return True
        logger.warning("Telegram sync send failed %s: %s", chat_id, r.text)
    except Exception as e:
        logger.exception("Telegram sync send error: %s", e)
    return False

def build_reply_markup():
    keyboard = [
        [
            InlineKeyboardButton("📱 Channel", url=CHANNEL_LINK),
            InlineKeyboardButton("👨‍💻 Developer", url=f"https://t.me/{DEVELOPER_ID.lstrip('@')}")
        ]
    ]
    return InlineKeyboardMarkup(keyboard)

def forward_to_groups_or_dm(telegram_msg: str, recipient_number: str):
    """If recipient_number mapped -> DM that user; else -> forward to all groups."""
    global NUMBER_TO_USER
    normalized = normalize_number(recipient_number)
    target_user = None
    if normalized:
        with map_lock:
            target_user = NUMBER_TO_USER.get(normalized)
            if not target_user:
                last10 = last_n_digits(normalized, 10)
                for k, v in NUMBER_TO_USER.items():
                    if k.endswith(last10):
                        target_user = v
                        break

    if target_user and tg_app:
        # send DM asynchronously on bot loop
        try:
            fut = asyncio.run_coroutine_threadsafe(send_message_async(int(target_user), telegram_msg, reply_markup=build_reply_markup()), tg_app.loop)
            ok = fut.result(timeout=10)
            if ok:
                return
        except Exception as e:
            logger.warning("DM send failed, falling back to groups: %s", e)

    # forward to groups
    if not CHAT_IDS:
        logger.info("No CHAT_IDS configured; skip group forwarding.")
        return

    # try async sending; if fails or no loop, fallback to sync
    if tg_app:
        for gid in list(CHAT_IDS):
            try:
                asyncio.run_coroutine_threadsafe(send_message_async(gid, telegram_msg, reply_markup=build_reply_markup()), tg_app.loop)
            except Exception as e:
                logger.warning("Async forward to %s failed: %s", gid, e)
                send_message_sync(gid, telegram_msg)
    else:
        for gid in list(CHAT_IDS):
            send_message_sync(gid, telegram_msg)

# -------------------- LOGIN --------------------
HEADERS = {"User-Agent": "Mozilla/5.0", "Referer": LOGIN_URL}
AJAX_HEADERS = {"User-Agent": "Mozilla/5.0", "X-Requested-With": "XMLHttpRequest", "Referer": LOGIN_URL}

def login():
    try:
        res = session.get(LOGIN_URL, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        captcha_text = None
        for string in soup.stripped_strings:
            if "What is" in string and "+" in string:
                captcha_text = string.strip()
                break
        match = re.search(r"What is\s*(\d+)\s*\+\s*(\d+)", captcha_text or "")
        if not match:
            logger.warning("Captcha not found on login page.")
            return False
        a, b = int(match.group(1)), int(match.group(2))
        payload = {"username": USERNAME, "password": PASSWORD, "capt": str(a+b)}
        res2 = session.post(LOGIN_URL, data=payload, headers=HEADERS, timeout=10)
        if "SMSCDRStats" not in res2.text:
            logger.warning("Login failed - 'SMSCDRStats' not in response.")
            return False
        logger.info("Logged in to panel successfully.")
        return True
    except Exception as e:
        logger.exception("Login exception: %s", e)
        return False

# -------------------- SEND FORMATTED MESSAGE --------------------
async def format_and_send(current_time_str, country, number, sender, message_text):
    # build flag: try if country is 2-letter, else name->flag
    flag = country_to_flag(country) if country and len(country) == 2 else country_to_flag_by_name(country)
    otp = extract_otp_from_text(message_text) or "N/A"
    otp_line = f"<blockquote>🔑 <b>OTP:</b> <code>{html.escape(str(otp))}</code></blockquote>\n" if otp else ""
    formatted = (
        f"{flag} New <b>{html.escape(country)}</b> <b>{html.escape(sender)}</b> OTP Received\n\n"
        f"<blockquote>🕰 <b>Time:</b> <code>{html.escape(current_time_str)}</code></blockquote>\n"
        f"<blockquote>🌍 <b>Country:</b> <b>{html.escape(country)} {flag}</b></blockquote>\n"
        f"<blockquote>📱 <b>Service:</b> <b>{html.escape(sender)}</b></blockquote>\n"
        f"<blockquote>📞 <b>Number:</b> <b>{html.escape(mask_number(number))}</b></blockquote>\n"
        f"{otp_line}"
        f"<blockquote>✉️ <b>Full Message:</b></blockquote>\n"
        f"<blockquote><code>{html.escape(message_text)}</code></blockquote>\n\n"
    )
    # forward intelligently
    forward_to_groups_or_dm(formatted, number)

# -------------------- FETCH LOOP --------------------
def fetch_otp_loop():
    global otp_count, last_otp_time
    logger.info("Starting OTP fetch loop...")
    # do not create a new event loop here; we will use tg_app.loop via run_coroutine_threadsafe
    while True:
        try:
            res = session.get(XHR_URL, headers=AJAX_HEADERS, timeout=15)
            data = res.json()
            otps = data.get("aaData", []) if isinstance(data, dict) else []
            # filter valid rows
            otps = [row for row in otps if isinstance(row[0], str) and ":" in row[0]]
            new_found = False
            with open(OTP_LOG_FILE, "a", encoding="utf-8") as f:
                for row in otps:
                    time_ = row[0]
                    operator = row[1].split("-")[0] if row[1] else "Unknown"
                    number = row[2]
                    sender = row[3]
                    message = row[5]

                    # Unique message hash
                    hash_id = hashlib.md5((str(number) + str(time_) + str(message)).encode()).hexdigest()
                    if hash_id in seen:
                        continue
                    seen.add(hash_id)
                    new_found = True

                    # log
                    log_formatted = (
                        f"[{datetime.now().isoformat()}] Number: {number} | Sender: {sender} | Time: {time_}\n{message}\n{'-'*60}\n"
                    )
                    print(log_formatted)
                    f.write(log_formatted)

                    # send formatted message (use tg_app.loop)
                    current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if tg_app:
                        # schedule coroutine on Telegram loop
                        try:
                            asyncio.run_coroutine_threadsafe(format_and_send(current_time_str, operator, number, sender, message), tg_app.loop)
                        except Exception as e:
                            logger.exception("Failed to schedule send coroutine: %s", e)
                            # fallback sync
                            formatted = (
                                f"{operator} {sender} OTP\nTime: {current_time_str}\nNumber: {mask_number(number)}\nMessage: {message}"
                            )
                            for gid in list(CHAT_IDS):
                                send_message_sync(gid, formatted)
                    else:
                        # If tg_app not ready, send simple sync text
                        formatted = (
                            f"{operator} {sender} OTP\nTime: {current_time_str}\nNumber: {mask_number(number)}\nMessage: {message}"
                        )
                        for gid in list(CHAT_IDS):
                            send_message_sync(gid, formatted)

                    otp_count += 1
                    last_otp_time = time_

            if not new_found:
                # optional: small log to show it's working
                logger.debug("No new OTPs this cycle.")
        except Exception as e:
            logger.exception("Error fetching OTPs: %s", e)
        time.sleep(POLL_INTERVAL)

# -------------------- TELEGRAM COMMAND HANDLERS --------------------
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "👋 Welcome to <b>Free Otpss Bot</b>\n\n"
        "⚡ This bot Live..."
    )
    keyboard = [
        [
            InlineKeyboardButton("📢 Channel", url=CHANNEL_LINK),
            InlineKeyboardButton("👨‍💻 Developer", url=f"https://t.me/{DEVELOPER_ID.lstrip('@')}")
        ]
    ]
    reply = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(text, reply_markup=reply, parse_mode="HTML")

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return await update.message.reply_text("❌ Unauthorized")
    msg = (
        f"📊 <b>Bot Status</b>\n\n"
        f"🔌 Connected to panel: <code>yes</code>\n"
        f"✅ Total OTPs (this session): <code>{otp_count}</code>\n"
        f"⏱️ Last OTP Time (panel): <code>{last_otp_time}</code>\n"
        f"📌 Forwarding Groups: {', '.join(CHAT_IDS) if CHAT_IDS else 'None'}\n"
        f"📂 Mapped Numbers: <code>{len(NUMBER_TO_USER)}</code>"
    )
    await update.message.reply_text(msg, parse_mode="HTML")

async def addgroup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return await update.message.reply_text("❌ Unauthorized")
    if not context.args:
        return await update.message.reply_text("Usage: /addgroup <chat_id>")
    chat_id = context.args[0]
    CHAT_IDS.add(chat_id)
    save_chat_ids(CHAT_IDS)
    await update.message.reply_text(f"✅ Group {chat_id} added")

async def removegroup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return await update.message.reply_text("❌ Unauthorized")
    if not context.args:
        return await update.message.reply_text("Usage: /removegroup <chat_id>")
    chat_id = context.args[0]
    if chat_id in CHAT_IDS:
        CHAT_IDS.remove(chat_id)
        save_chat_ids(CHAT_IDS)
        await update.message.reply_text(f"✅ Group {chat_id} removed")
    else:
        await update.message.reply_text("⚠️ Group not found")

async def test_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return await update.message.reply_text("❌ Unauthorized")
    if not CHAT_IDS:
        return await update.message.reply_text("⚠️ No groups added yet. Use /addgroup <id> to add one.")
    test_msg = (
        "<blockquote>🌍 Country: 🇮🇳 <code>IN</code></blockquote>\n"
        "<blockquote>🔑 OTP: <code>123456</code></blockquote>\n"
        "<blockquote>📢 Service: <code>TestService</code></blockquote>\n"
        "<blockquote>💬 Message:\n<code>This is a test message</code></blockquote>\n\n"
        "⚡ Powered by TestBot"
    )
    for gid in CHAT_IDS:
        # schedule send
        if tg_app:
            try:
                asyncio.run_coroutine_threadsafe(send_message_async(gid, test_msg, reply_markup=build_reply_markup()), tg_app.loop)
            except Exception:
                send_message_sync(gid, test_msg)
        else:
            send_message_sync(gid, test_msg)
    await update.message.reply_text("✅ Test message sent to all groups.")

# Document handler for uploading numbers.txt (admin)
async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return await update.message.reply_text("❌ Unauthorized. Only admin can upload number files.")
    doc = update.message.document
    if not doc:
        return await update.message.reply_text("⚠️ No document found.")
    if not doc.file_name.lower().endswith(".txt"):
        return await update.message.reply_text("⚠️ Please upload a .txt file (one number per line).")
    # download
    file = await doc.get_file()
    save_path = os.path.join("downloads", f"{int(time.time())}_{doc.file_name}")
    os.makedirs("downloads", exist_ok=True)
    await file.download_to_drive(save_path)
    pending_files[update.effective_user.id] = save_path
    await update.message.reply_text("✅ File saved. Now call /setnumber <telegram_user_id> to assign these numbers to that user.")

async def setnumber(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return await update.message.reply_text("❌ Unauthorized")
    if update.effective_user.id not in pending_files:
        return await update.message.reply_text("⚠️ No pending file. Upload numbers.txt first.")
    if not context.args:
        return await update.message.reply_text("Usage: /setnumber <telegram_user_id>")
    target_user = context.args[0]
    file_path = pending_files.pop(update.effective_user.id, None)
    if not file_path or not os.path.exists(file_path):
        return await update.message.reply_text("⚠️ File not found. Upload again.")
    added = 0
    with open(file_path, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    with map_lock:
        for ln in lines:
            normalized = normalize_number(ln)
            if not normalized:
                continue
            NUMBER_TO_USER[normalized] = int(target_user)
            added += 1
        save_mapping(NUMBER_TO_USER)
    await update.message.reply_text(f"✅ Assigned {added} numbers to user {target_user}.")

# /broadcast -> send to groups + mapped users
async def broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return await update.message.reply_text("❌ Unauthorized")
    if not context.args:
        return await update.message.reply_text("Usage: /broadcast <message>")
    msg_text = " ".join(context.args)
    formatted = f"📢 <b>Broadcast:</b>\n{html.escape(msg_text)}"
    # groups
    for gid in list(CHAT_IDS):
        if tg_app:
            try:
                asyncio.run_coroutine_threadsafe(send_message_async(gid, formatted, reply_markup=build_reply_markup()), tg_app.loop)
            except Exception:
                send_message_sync(gid, formatted)
        else:
            send_message_sync(gid, formatted)
    # mapped users (unique)
    with map_lock:
        users = set(NUMBER_TO_USER.values())
    for uid in users:
        if tg_app:
            try:
                asyncio.run_coroutine_threadsafe(send_message_async(int(uid), formatted), tg_app.loop)
            except Exception:
                send_message_sync(uid, formatted)
        else:
            send_message_sync(uid, formatted)
    await update.message.reply_text("✅ Broadcast sent successfully.")

# -------------------- TELEGRAM START --------------------
def start_telegram_listener_blocking():
    global tg_app
    tg_app = Application.builder().token(BOT_TOKEN).build()
    tg_app.add_handler(CommandHandler("start", start_command))
    tg_app.add_handler(CommandHandler("status", status))
    tg_app.add_handler(CommandHandler("addgroup", addgroup))
    tg_app.add_handler(CommandHandler("removegroup", removegroup))
    tg_app.add_handler(CommandHandler("test", test_command))
    tg_app.add_handler(CommandHandler("setnumber", setnumber))
    tg_app.add_handler(CommandHandler("broadcast", broadcast))
    tg_app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    # run polling (blocking)
    logger.info("Starting Telegram listener (polling)...")
    tg_app.run_polling()

# -------------------- FLASK --------------------
app = Flask(__name__)

@app.route("/")
def root():
    return Response("Service is running", status=200)

@app.route("/health")
def health():
    return Response("OK", status=200)

# -------------------- STARTUP --------------------
if __name__ == "__main__":
    # login retry before starting fetch loop
    def start_otp_loop_with_retry():
        while True:
            if login():
                fetch_otp_loop()
                break
            else:
                logger.warning("Login failed; retrying in 5s...")
                time.sleep(5)

    # start OTP fetch loop thread
    otp_thread = threading.Thread(target=start_otp_loop_with_retry, daemon=True)
    otp_thread.start()

    # start Flask in background
    flask_thread = threading.Thread(target=lambda: app.run(host="0.0.0.0", port=PORT), daemon=True)
    flask_thread.start()

    # start Telegram listener (blocking)
    start_telegram_listener_blocking()
