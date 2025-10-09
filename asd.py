import requests
import re
import time
import hashlib
import html
from bs4 import BeautifulSoup
from flask import Flask, Response
import threading
import telegram
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
import asyncio
from pymongo import MongoClient
import os
import logging
import pycountry
from datetime import datetime
from telegram.ext import Application, CommandHandler, ContextTypes

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

EXTRA_CODES = {"Kosovo": "XK"}  # special cases

# Seen cache with expiry
seen_cache = {}  # {hash_id: timestamp}
CACHE_TTL = 600  # 10 minutes

def country_to_flag(country_name: str) -> str:
    code = EXTRA_CODES.get(country_name)
    if not code:
        try:
            country = pycountry.countries.lookup(country_name)
            code = country.alpha_2
        except LookupError:
            return ""
    return "".join(chr(127397 + ord(c)) for c in code.upper())

# Configuration
LOGIN_URL = "http://51.89.99.105/NumberPanel/signin"
XHR_URL = "http://51.89.99.105/NumberPanel/agent/res/data_smscdr.php?fdate1=2025-09-05%2000:00:00&fdate2=2026-09-04%2023:59:59&frange=&fclient=&fnum=&fcli=&fgdate=&fgmonth=&fgrange=&fgclient=&fgnumber=&fgcli=&fg=0&sEcho=1&iColumns=9&sColumns=%2C%2C%2C%2C%2C%2C%2C%2C&iDisplayStart=0&iDisplayLength=3&mDataProp_0=0&sSearch_0=&bRegex_0=false&bSearchable_0=true&bSortable_0=true&mDataProp_1=1&sSearch_1=&bRegex_1=false&bSearchable_1=true&bSortable_1=true&mDataProp_2=2&sSearch_2=&bRegex_2=false&bSearchable_2=true&bSortable_2=true&mDataProp_3=3&sSearch_3=&bRegex_3=false&bSearchable_3=true&bSortable_3=true&mDataProp_4=4&sSearch_4=&bRegex_4=false&bSearchable_4=true&bSortable_4=true&mDataProp_5=5&sSearch_5=&bRegex_5=false&bSearchable_5=true&bSortable_5=true&mDataProp_6=6&sSearch_6=&bRegex_6=false&bSearchable_6=true&bSortable_6=true&mDataProp_7=7&sSearch_7=&bRegex_7=false&bSearchable_7=true&bSortable_7=true&mDataProp_8=8&sSearch_8=&bRegex_8=false&bSearchable_8=true&bSortable_8=false&sSearch=&bRegex=false&iSortCol_0=0&sSortDir_0=desc&iSortingCols=1&_=1756968295291"
USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")
BOT_TOKEN = os.getenv("BOT_TOKEN")
DEVELOPER_ID = "@hiden_25"
CHANNEL_LINK = "@freeotpss"
# Headers
HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Referer": "http://51.89.99.105/NumberPanel/login"
}
AJAX_HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "X-Requested-With": "XMLHttpRequest",
    "Referer": "http://51.89.99.105/NumberPanel/agent/SMSCDRStats"
}

# Initialize Flask app
app = Flask(__name__)

# Initialize Telegram bot
bot = telegram.Bot(token=BOT_TOKEN)

# Session and state
session = requests.Session()
seen = set()
# ---------------- MongoDB Configuration ----------------
MONGO_URI = "mongodb+srv://number25:number25@cluster0.kdeklci.mongodb.net/"
MONGO_DB_NAME = "otp_database"
MONGO_COLLECTION_NAME = "numbers"

mongo_client = MongoClient(MONGO_URI)
mongo_db = mongo_client[MONGO_DB_NAME]
numbers_collection = mongo_db[MONGO_COLLECTION_NAME]

# ---------------- OTP Extractor ----------------
def extract_otp(message: str) -> str | None:
    message = message.strip()

    # 1) OTP keywords ke aas paas (digits/letters mix allowed)
    keyword_regex = re.search(r"(otp|code|pin|password)[^\da-zA-Z]{0,10}([a-zA-Z0-9\-\s]{4,12})", message, re.I)
    if keyword_regex:
        return re.sub(r"\W", "", keyword_regex.group(2))

    # 2) Reverse form: "123456 is your OTP"
    reverse_regex = re.search(r"([a-zA-Z0-9\-\s]{4,12})[^\w]{0,10}(otp|code|pin|password)", message, re.I)
    if reverse_regex:
        return re.sub(r"\W", "", reverse_regex.group(1))

    # 3) Standalone 4–8 digit number (ignoring years)
    generic_regex = re.findall(r"\b\d{4,8}\b", message)
    if generic_regex:
        for num in generic_regex:
            if not (1900 <= int(num) <= 2099):
                return num

    return None
# ---------------- Telegram Flood-Safe ----------------
async def send_telegram_message_safe(bot, chat_id, text, reply_markup):
    retries = 3
    for attempt in range(retries):
        try:
            await bot.send_message(
                chat_id=chat_id,
                text=text,
                reply_markup=reply_markup,
                disable_web_page_preview=True,
                parse_mode="HTML"
            )
            return True
        except Exception as e:
            print(f"⚠️ Error sending to {chat_id} (attempt {attempt+1}): {e}")
            await asyncio.sleep(2 * (attempt + 1))  # exponential backoff
    return False

# Multiple group IDs
CHAT_IDS = [
    "-1001926462756",
    "-1002822806611",
    "-1002076542006",
    "-1002882678200",
    "-1003012995316",
    "-1002293228917",
    "-1002897863211",
    "-1002633885396",
    "-1002845705646",
    "-1003091760661",
    "-1003020628799",
    "-1002694707754",
    "-1003048784329",
    "-1002711511326",
    "-1002982683241",
    "-1002795006142",
    "-1003011711874",
    "-1003128643551",
    "-1002631105228",
    "-1003104891845",
    "-1002889971843",
    "-1002651756646",
    "-1002983499341",
    "-1002727905513",
    "-1002589569393",
    "-1002890726608",
    "-1002765383813",
    "-1002978773848",
    "-1002203441277",
    "-1002853296881",
    "-1002329314110",
    "-1002887327314",
    "-1003128279789",
    "-1002836347659",
    "-1003193519871"
]

def save_number_to_db(number: str):
    """Save unique number to MongoDB"""
    number = number.strip()
    if not number:
        return

    try:
        # Avoid duplicates
        if not numbers_collection.find_one({"number": number}):
            numbers_collection.insert_one({
                "number": number,
                "timestamp": datetime.now()
            })
            print(f"✅ Saved to MongoDB: {number}")
        else:
            print(f"⚠️ Number already exists in DB: {number}")
    except Exception as e:
        print(f"❌ MongoDB insert error: {e}")

# ---------------- Final Send Function ----------------
async def send_telegram_message(current_time, country, number, sender, message):
    flag = country_to_flag(country)
    otp = extract_otp(message)  # 🔎 extract OTP here
    otp_line = f"<blockquote>🔑 <b>OTP:</b> <code>{html.escape(otp)}</code></blockquote>\n" if otp else ""

    formatted = (
        f"{flag} <b>OTP Alert from {country}</b>\n\n"
        f"<blockquote>⏰ <b>Time:</b> {html.escape(str(current_time))}</blockquote>\n"
        f"<blockquote>🌍 <b>Location:</b> {html.escape(country)} {flag}</blockquote>\n"
        f"<blockquote>📱 <b>Service:</b> {html.escape(sender)}</blockquote>\n"
        f"<blockquote>☎️ <b>Number:</b> {html.escape(number)}</blockquote>\n"
        f"{otp_line}"
        f"<blockquote>📝 <b>Message Preview:</b></blockquote>\n"
        f"<blockquote><code>{html.escape(message)}</code></blockquote>\n"
    )

    keyboard = [
        [InlineKeyboardButton("☘ Channel", url=f"https://t.me/{CHANNEL_LINK.lstrip('@')}")],
        [InlineKeyboardButton("👨‍💻 Developer", url=f"https://t.me/{DEVELOPER_ID.lstrip('@')}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await asyncio.sleep(1)  # Delay to avoid flood

    # ✅ Send formatted OTP message to all groups
    for chat_id in CHAT_IDS:
        await send_telegram_message_safe(bot, chat_id, formatted, reply_markup)

    # ✅ Save number to MongoDB instead of sending to group
    save_number_to_db(number)

# ---------------- Login ----------------
def login():
    res = session.get("http://51.89.99.105/NumberPanel/login", headers=HEADERS)
    soup = BeautifulSoup(res.text, "html.parser")

    captcha_text = None
    for string in soup.stripped_strings:
        if "What is" in string and "+" in string:
            captcha_text = string.strip()
            break

    match = re.search(r"What is\s*(\d+)\s*\+\s*(\d+)", captcha_text or "")
    if not match:
        print("❌ Captcha not found.")
        return False

    a, b = int(match.group(1)), int(match.group(2))
    captcha_answer = str(a + b)
    print(f"✅ Captcha solved: {a} + {b} = {captcha_answer}")

    payload = {"username": USERNAME, "password": PASSWORD, "capt": captcha_answer}
    res = session.post(LOGIN_URL, data=payload, headers=HEADERS)
    if "SMSCDRStats" not in res.text:
        print("❌ Login failed.")
        return False

    print("✅ Logged in successfully.")
    return True

# ---------------- Fetch OTP Loop ----------------
def fetch_otp_loop():
    print("\n🔄 Starting OTP fetch loop...\n")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    while True:
        try:
            res = session.get(XHR_URL, headers=AJAX_HEADERS)
            data = res.json()
            otps = data.get("aaData", [])

            otps = [row for row in otps if isinstance(row[0], str) and ":" in row[0]]

            new_found = False
            with open("otp_logs.txt", "a", encoding="utf-8") as f:
                for row in otps:
                    time_ = row[0]
                    operator = row[1].split("-")[0]
                    number = row[2]
                    sender = row[3]
                    message = row[5]

                    hash_id = hashlib.md5((number + time_ + message).encode()).hexdigest()
                    if hash_id in seen:
                        continue
                    seen.add(hash_id)
                    new_found = True

                    log_formatted = (
                        f"📱 Number: {number}\n"
                        f"🏷️ Sender ID: {sender}\n"
                        f"💬 Message: {message}\n"
                        f"{'-'*60}"
                    )
                    print(log_formatted)
                    f.write(log_formatted + "\n")

                    loop.run_until_complete(send_telegram_message(time_, operator, number, sender, message))

            if not new_found:
                print("⏳ No new OTPs.")
        except Exception as e:
            print("❌ Error fetching OTPs:", e)

        time.sleep(1.2)

# ---------------- Flask Routes ----------------
@app.route('/health')
def health():
    return Response("OK", status=200)

@app.route("/")
def root():
    logger.info("Root endpoint requested")
    return Response("OK", status=200)

# ---------------- Telegram Bot ----------------
async def start_command(update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("✅ Bot is Active & Running! Contact If Any Problem @hiden_25")

def start_telegram_listener():
    tg_app = Application.builder().token(BOT_TOKEN).build()
    tg_app.add_handler(CommandHandler("start", start_command))
    tg_app.run_polling()

# ---------------- Start Everything ----------------
def start_otp_loop():
    if login():
        fetch_otp_loop()

if __name__ == '__main__':
    # OTP loop background me
    otp_thread = threading.Thread(target=start_otp_loop, daemon=True)
    otp_thread.start()

    # Flask background me
    flask_thread = threading.Thread(target=lambda: app.run(host='0.0.0.0', port=8080), daemon=True)
    flask_thread.start()

    # Telegram bot MAIN thread me
    start_telegram_listener() 
