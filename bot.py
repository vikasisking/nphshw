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
import os
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
import pycountry
from datetime import datetime
from telegram.ext import Application, CommandHandler, ContextTypes

# ----------------------------------------------------
# ✅ Version Info
# ----------------------------------------------------
BOT_VERSION = "v0.2.0"

# ----------------------------------------------------
# Config
# ----------------------------------------------------
current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
EXTRA_CODES = {"Kosovo": "XK"}  # special cases

def country_to_flag(country_name: str) -> str:
    code = EXTRA_CODES.get(country_name)
    if not code:
        try:
            country = pycountry.countries.lookup(country_name)
            code = country.alpha_2
        except LookupError:
            return ""
    return "".join(chr(127397 + ord(c)) for c in code.upper())

LOGIN_URL = "http://51.89.99.105/NumberPanel/signin"
XHR_URL = "http://51.89.99.105/NumberPanel/client/res/data_smscdr.php?fdate1=2025-09-05%2000:00:00&fdate2=2026-09-04%2023:59:59&frange=&fclient=&fnum=&fcli=&fgdate=&fgmonth=&fgrange=&fgclient=&fgnumber=&fgcli=&fg=0&sEcho=1&iColumns=9&sColumns=%2C%2C%2C%2C%2C%2C%2C%2C&iDisplayStart=0&iDisplayLength=01&mDataProp_0=0&sSearch_0=&bRegex_0=false&bSearchable_0=true&bSortable_0=true&mDataProp_1=1&sSearch_1=&bRegex_1=false&bSearchable_1=true&bSortable_1=true&mDataProp_2=2&sSearch_2=&bRegex_2=false&bSearchable_2=true&bSortable_2=true&mDataProp_3=3&sSearch_3=&bRegex_3=false&bSearchable_3=true&bSortable_3=true&mDataProp_4=4&sSearch_4=&bRegex_4=false&bSearchable_4=true&bSortable_4=true&mDataProp_5=5&sSearch_5=&bRegex_5=false&bSearchable_5=true&bSortable_5=true&mDataProp_6=6&sSearch_6=&bRegex_6=false&bSearchable_6=true&bSortable_6=true&mDataProp_7=7&sSearch_7=&bRegex_7=false&bSearchable_7=true&bSortable_7=true&mDataProp_8=8&sSearch_8=&bRegex_8=false&bSearchable_8=true&bSortable_8=false&sSearch=&bRegex=false&iSortCol_0=0&sSortDir_0=desc&iSortingCols=1&_=1756968295291"
USERNAME = "developer25"
PASSWORD = "developer25"
BOT_TOKEN = "8320732728:AAFQgKIOTPvOaOeaDe6YVX0689YysMs4v18"
DEVELOPER_ID = "@hiden_25"
CHANNEL_LINK = "https://t.me/freeotpss"

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Referer": "http://51.89.99.105/NumberPanel/login"
}
AJAX_HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "X-Requested-With": "XMLHttpRequest",
    "Referer": "http://51.89.99.105/NumberPanel/client/SMSCDRStats"
}

# ----------------------------------------------------
# Initialize
# ----------------------------------------------------
app = Flask(__name__)
bot = telegram.Bot(token=BOT_TOKEN)
session = requests.Session()
seen = set()

# ----------------------------------------------------
# Login
# ----------------------------------------------------
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

# ----------------------------------------------------
# Utilities
# ----------------------------------------------------
def mask_number(number):
    if len(number) <= 6:
        return number
    mid = len(number) // 2
    return number[:mid-1] + "***" + number[mid+2:]

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
    "-1002983499341",
    "-1002795006142",
    "-1003011711874",
    "-1003128643551",
    "-1002631105228",
    "-1003104891845",
    "-1002889971843",
    "-1002651756646",
    "-1003132637703",
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
    "-1003193519871",
    "-1003017848131",
    "-1002968656301",
    "-1002843389091",
    "-1002909161587",
    "-1002984994556",
    "-1002750251047",
    "-1002841203572",
    "-1002834841860"
]
ADMIN_ID = 7761576669
ADMIN_CHAT_ID = "7761576669"

# ----------------------------------------------------
# Admin Alert (Only Group Send Failures)
# ----------------------------------------------------
async def alert_admin_on_group_error(error, chat_id):
    if str(chat_id).startswith("-100"):  # sirf groups
        try:
            await bot.send_message(
                chat_id=ADMIN_CHAT_ID,
                text=f"⚠️ Failed to send OTP to Group {chat_id}\nReason: {error}"
            )
        except Exception as e:
            logger.error(f"⚠️ Failed to alert admin: {e}")

# ----------------------------------------------------
# OTP Extractor
# ----------------------------------------------------
def extract_otp(message: str) -> str | None:
    message = message.strip()
    keyword_regex = re.search(r"(otp|code|pin|password)[^\d]{0,10}(\d[\d\-]{3,8})", message, re.I)
    if keyword_regex:
        return re.sub(r"\D", "", keyword_regex.group(2))

    reverse_regex = re.search(r"(\d[\d\-]{3,8})[^\w]{0,10}(otp|code|pin|password)", message, re.I)
    if reverse_regex:
        return re.sub(r"\D", "", reverse_regex.group(1))

    generic_regex = re.findall(r"\b\d[\d\-]{3,8}\b", message)
    if generic_regex:
        for num in generic_regex:
            num_clean = re.sub(r"\D", "", num)
            if 4 <= len(num_clean) <= 8 and not (1900 <= int(num_clean) <= 2099):
                return num_clean
    return None

# ----------------------------------------------------
# Send Telegram Message
# ----------------------------------------------------
async def send_telegram_message(current_time, country, number, sender, message):
    flag = country_to_flag(country)
    otp = extract_otp(message)

    otp_section = (
        f"\n🔐 <b>OTP:</b> <code>{html.escape(otp)}</code>\n"
        if otp else ""
    )

    formatted = (
        f"🚨 <b>New OTP Received!</b>\n"
        f"{flag} <b>{country}</b> | <b>{sender}</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🕓 <b>Time:</b> {html.escape(str(current_time))}\n"
        f"📞 <b>Number:</b> <code>{html.escape(mask_number(number))}</code>\n"
        f"{otp_section}"
        f"━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"💬 <b>Full Message:</b>\n"
        f"<code>{html.escape(message)}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━"
    )

    keyboard = [
        [InlineKeyboardButton("📱 Visit Channel", url=f"{CHANNEL_LINK}")],
        [InlineKeyboardButton("👨‍💻 Contact Dev", url=f"https://t.me/{DEVELOPER_ID.lstrip('@')}")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await asyncio.sleep(1)

    for chat_id in CHAT_IDS:
        try:
            await bot.send_message(
                chat_id=chat_id,
                text=formatted,
                reply_markup=reply_markup,
                disable_web_page_preview=True,
                parse_mode="HTML"
            )
        except Exception as e:
            logger.error(f"❌ Failed to send to {chat_id}: {e}")
            await alert_admin_on_group_error(e, chat_id)

# ----------------------------------------------------
# Telegram Commands
# ----------------------------------------------------
async def start_command(update, context: ContextTypes.DEFAULT_TYPE):
    start_message = (
        "🤖 <b>Number Bot Status</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"✅ <b>Status:</b> Active & Running\n"
        f"⚙️ <b>Version:</b> <code>{BOT_VERSION}</code>\n"
        f"👨‍💻 <b>Developer:</b> {DEVELOPER_ID}\n"
        f"📢 <b>Official Channel:</b> <a href='{CHANNEL_LINK}'>Click Here</a>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n"
        "💡 Use this bot to monitor OTP messages in real-time."
    )

    keyboard = [
        [InlineKeyboardButton("📱 Visit Channel", url=f"{CHANNEL_LINK}")],
        [InlineKeyboardButton("👨‍💻 Contact Dev", url=f"https://t.me/{DEVELOPER_ID.lstrip('@')}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        start_message,
        parse_mode="HTML",
        disable_web_page_preview=True,
        reply_markup=reply_markup
    )
    
async def add_chat(update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return await update.message.reply_text("❌ You are not allowed to use this command.")
    if not context.args:
        return await update.message.reply_text("Usage: /addchat <chat_id>")

    chat_id = context.args[0]
    if chat_id not in CHAT_IDS:
        CHAT_IDS.append(chat_id)
        await update.message.reply_text(f"✅ Chat ID {chat_id} added.")
    else:
        await update.message.reply_text("⚠️ Already in the list.")

async def remove_chat(update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return await update.message.reply_text("❌ You are not allowed to use this command.")
    if not context.args:
        return await update.message.reply_text("Usage: /removechat <chat_id>")

    chat_id = context.args[0]
    if chat_id in CHAT_IDS:
        CHAT_IDS.remove(chat_id)
        await update.message.reply_text(f"✅ Chat ID {chat_id} removed.")
    else:
        await update.message.reply_text("⚠️ Not found in the list.")

def start_telegram_listener():
    tg_app = Application.builder().token(BOT_TOKEN).build()
    tg_app.add_handler(CommandHandler("start", start_command))
    tg_app.add_handler(CommandHandler("addchat", add_chat))
    tg_app.add_handler(CommandHandler("removechat", remove_chat))
    tg_app.run_polling()

# ----------------------------------------------------
# OTP Fetch Loop
# ----------------------------------------------------
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
                    message = row[4]

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

# ----------------------------------------------------
# Flask Endpoints
# ----------------------------------------------------
@app.route('/health')
def health():
    return Response("OK", status=200)

@app.route("/")
def root():
    logger.info("Root endpoint requested")
    return Response("OK", status=200)

# ----------------------------------------------------
# Start Everything
# ----------------------------------------------------
def start_otp_loop():
    if login():
        fetch_otp_loop()

if __name__ == '__main__':
    otp_thread = threading.Thread(target=start_otp_loop, daemon=True)
    otp_thread.start()

    flask_thread = threading.Thread(target=lambda: app.run(host='0.0.0.0', port=8080), daemon=True)
    flask_thread.start()

    start_telegram_listener()
