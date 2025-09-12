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
    
# Configuration
LOGIN_URL = "http://51.89.99.105/NumberPanel/signin"
XHR_URL = "http://51.89.99.105/NumberPanel/agent/res/data_smscdr.php?fdate1=2025-09-05%2000:00:00&fdate2=2026-09-04%2023:59:59&frange=&fclient=&fnum=&fcli=&fgdate=&fgmonth=&fgrange=&fgclient=&fgnumber=&fgcli=&fg=0&sEcho=1&iColumns=9&sColumns=%2C%2C%2C%2C%2C%2C%2C%2C&iDisplayStart=0&iDisplayLength=2&mDataProp_0=0&sSearch_0=&bRegex_0=false&bSearchable_0=true&bSortable_0=true&mDataProp_1=1&sSearch_1=&bRegex_1=false&bSearchable_1=true&bSortable_1=true&mDataProp_2=2&sSearch_2=&bRegex_2=false&bSearchable_2=true&bSortable_2=true&mDataProp_3=3&sSearch_3=&bRegex_3=false&bSearchable_3=true&bSortable_3=true&mDataProp_4=4&sSearch_4=&bRegex_4=false&bSearchable_4=true&bSortable_4=true&mDataProp_5=5&sSearch_5=&bRegex_5=false&bSearchable_5=true&bSortable_5=true&mDataProp_6=6&sSearch_6=&bRegex_6=false&bSearchable_6=true&bSortable_6=true&mDataProp_7=7&sSearch_7=&bRegex_7=false&bSearchable_7=true&bSortable_7=true&mDataProp_8=8&sSearch_8=&bRegex_8=false&bSearchable_8=true&bSortable_8=false&sSearch=&bRegex=false&iSortCol_0=0&sSortDir_0=desc&iSortingCols=1&_=1756968295291"
USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")
BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = "-1001926462756"
DEVELOPER_ID = "@hiden_25"  # Replace with your Telegram ID
CHANNEL_LINK = "@freeotpss" # Replace with your Telegram channel ID

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

# Login function
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

    payload = {
        "username": USERNAME,
        "password": PASSWORD,
        "capt": captcha_answer
    }

    res = session.post(LOGIN_URL, data=payload, headers=HEADERS)
    if "SMSCDRStats" not in res.text:
        print("❌ Login failed.")
        return False

    print("✅ Logged in successfully.")
    return True

# Mask phone number (show first 4 and last 3 digits)
def mask_number(number):
    if len(number) <= 6:
        return number  # agar chhota number hai to mask na karo
    # sirf middle 3 digits mask honge
    mid = len(number) // 2
    return number[:mid-1] + "***" + number[mid+2:]


# Send message to Telegram with inline buttons
# Multiple group IDs
CHAT_IDS = [
    "-1001926462756",
    "-1002840367665",
    "-1002091416812",
    "-1002943235559",
    "-1002940216589", #otp log# Group 1
    "-1002923895005",
    "-1003082242175",
    "-1003066997237",
    "-1002909865915",
    "-1001934899005",
    "-1002923836751",
    "-1002932258910",
    "-1002915052882",
    "-1002819495262",
    "-1002949721254",
    "-1002940934786",
    "-1002822806611",
    "-1003017848131",
    "-1002442614918",
    "-1003099177664",
    "-1002940428585",
    "-1002861375537"
]

import re

def extract_otp(message: str) -> str | None:
    """
    Smart OTP extractor:
    - Detects numbers with OTP keywords (otp, code, pin, password)
    - Otherwise finds any standalone 4–8 digit number
    - Ignores years like 2024, 2025
    """
    message = message.strip()

    # Case 1: keyword + number (e.g. "Your OTP is 123456")
    keyword_regex = re.search(r"(otp|code|pin|password)[^\d]{0,10}(\d{4,8})", message, re.I)
    if keyword_regex:
        return keyword_regex.group(2)

    # Case 2: any 4–8 digit standalone number
    generic_regex = re.findall(r"\b\d{4,8}\b", message)
    if generic_regex:
        for num in generic_regex:
            if not (1900 <= int(num) <= 2099):  # skip years
                return num

    return None

# Send message to Telegram with inline buttons
import re, html
from telegram import InlineKeyboardButton, InlineKeyboardMarkup

# ✅ OTP extractor
def extract_otp(message: str) -> str | None:
    message = message.strip()

    # 1) OTP/Code ke aas-paas digits (dash ko ignore karke)
    keyword_regex = re.search(r"(otp|code|pin|password)[^\d]{0,10}(\d[\d\-]{3,8})", message, re.I)
    if keyword_regex:
        return re.sub(r"\D", "", keyword_regex.group(2))  # non-digits remove

    # 2) Reverse form: "123456 is your login code"
    reverse_regex = re.search(r"(\d[\d\-]{3,8})[^\w]{0,10}(otp|code|pin|password)", message, re.I)
    if reverse_regex:
        return re.sub(r"\D", "", reverse_regex.group(1))

    # 3) Any standalone 4–8 digit number (ignoring years)
    generic_regex = re.findall(r"\b\d[\d\-]{3,8}\b", message)
    if generic_regex:
        for num in generic_regex:
            num_clean = re.sub(r"\D", "", num)
            if 4 <= len(num_clean) <= 8 and not (1900 <= int(num_clean) <= 2099):
                return num_clean

    return None



# ✅ Final send function
async def send_telegram_message(current_time, country, number, sender, message):
    flag = country_to_flag(country)
    otp = extract_otp(message)  # 🔎 extract OTP here
    otp_line = f"<blockquote>🔑 <b>OTP:</b> <code>{html.escape(otp)}</code></blockquote>\n" if otp else ""

    formatted = (
    f"{flag} <b>OTP Alert from {country}</b>\n\n"
    f"<blockquote>⏰ <b>Time:</b> {html.escape(str(current_time))}</blockquote>\n"
    f"<blockquote>🌍 <b>Location:</b> {html.escape(country)} {flag}</blockquote>\n"
    f"<blockquote>📱 <b>Service:</b> {html.escape(sender)}</blockquote>\n"
    f"<blockquote>☎️ <b>Number:</b> {html.escape(mask_number(number))}</blockquote>\n"
    f"{otp_line}"  # ✅ OTP line only if available
    f"<blockquote>📝 <b>Message Preview:</b></blockquote>\n"
    f"<blockquote><code>{html.escape(message)}</code></blockquote>\n\n"
   # f"<i>🔗 Designed by <a href='https://t.me/freeotpss'>H2I Free OTPss</a></i>"
)


    keyboard = [
         [
            InlineKeyboardButton("☘ Channel", url=f"https://t.me/{CHANNEL_LINK.lstrip('@')}"),
         
        ],
        [
            InlineKeyboardButton("👨‍💻 Developer", url=f"https://t.me/{DEVELOPER_ID.lstrip('@')}"),
         
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    # Delay to avoid flood
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


from telegram.ext import Application, CommandHandler, ContextTypes

# /start ka handler
async def start_command(update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("✅ Bot is Active & Running! Contact If Any Problem @hiden_25")

def start_telegram_listener():
    tg_app = Application.builder().token(BOT_TOKEN).build()
    tg_app.add_handler(CommandHandler("start", start_command))
    tg_app.run_polling()


# Fetch OTPs and send to Telegram
def fetch_otp_loop():
    print("\n🔄 Starting OTP fetch loop...\n")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    while True:
        try:
            res = session.get(XHR_URL, headers=AJAX_HEADERS)
            data = res.json()
            otps = data.get("aaData", [])

            # Remove the last summary row
            otps = [row for row in otps if isinstance(row[0], str) and ":" in row[0]]

            new_found = False
            with open("otp_logs.txt", "a", encoding="utf-8") as f:
                for row in otps:
                    time_ = row[0]
                    operator = row[1].split("-")[0]

                    number = row[2]
                    sender = row[3]
                    message = row[5]

                    # Unique message hash
                    hash_id = hashlib.md5((number + time_ + message).encode()).hexdigest()
                    if hash_id in seen:
                        continue
                    seen.add(hash_id)
                    new_found = True

                    # Log full details to file
                    log_formatted = (
                        
                        f"📱 Number:      {number}\n"
                        f"🏷️ Sender ID:   {sender}\n"
                        f"💬 Message:     {message}\n"
                        f"{'-'*60}"
                    )
                    print(log_formatted)
                    f.write(log_formatted + "\n")

                    # Send masked and formatted message to Telegram
                    loop.run_until_complete(send_telegram_message(time_, operator, number, sender, message))


            if not new_found:
                print("⏳ No new OTPs.")
        except Exception as e:
            print("❌ Error fetching OTPs:", e)

        time.sleep(1.2)

# Health check endpoint
@app.route('/health')
def health():
    return Response("OK", status=200)
@app.route("/")
def root():
    logger.info("Root endpoint requested")
    return Response("OK", status=200)
    
# Start the OTP fetching loop in a separate thread
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
