import json
import os
import sys
import urllib.parse

# Build Telegram Bot API URL for sendMediaGroup with 2 documents.
# Usage: python3 .github/scripts/telegram_url.py <chat_id>
#
# Required env:
# - BOT_TOKEN
# - COMMIT_MESSAGE
# - COMMIT_URL
# - COMMIT_ID
#
# Optional env:
# - MESSAGE_THREAD_ID

bot_token = os.environ["BOT_TOKEN"]
chat_id = sys.argv[1]

url = f"https://api.telegram.org/bot{bot_token}"
url += f"/sendMediaGroup?chat_id={urllib.parse.quote(chat_id)}"

thread_id = os.environ.get("MESSAGE_THREAD_ID", "").strip()
if thread_id:
    url += f"&message_thread_id={urllib.parse.quote(thread_id)}"

url += "&media="

# https://core.telegram.org/bots/api#markdownv2-style
msg = os.environ.get("COMMIT_MESSAGE", "")
for c in ["\\", "_", "*", "[", "]", "(", ")", "~", "`", ">", "#", "+", "-", "=", "|", "{", "}", ".", "!"]:
    msg = msg.replace(c, f"\\{c}")

commit_url = os.environ.get("COMMIT_URL", "")
commit_id = os.environ.get("COMMIT_ID", "")[:7]

caption = f"[{commit_id}]({commit_url})\n{msg}"[:1024]

data = json.dumps(
    [
        {"type": "document", "media": "attach://Release1"},
        {"type": "document", "media": "attach://Release2", "caption": caption, "parse_mode": "MarkdownV2"},
    ]
)

url += urllib.parse.quote(data)
print(url)

