#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
try:
    from access_tokens import TG_BOT_TOKEN, TG_CHAT_ID
except ImportError:
    TG_BOT_TOKEN = "YOUR_TOKEN"
    TG_CHAT_ID = "YOUR_CHAT_ID"

def send_to_telegram(message):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return
    
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TG_CHAT_ID,
        "text": message,
        "parse_mode": "HTML" # Optional if one uses tags
    }
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
    except Exception as e:
        print(f"❌ Telegram Error: {e}")
