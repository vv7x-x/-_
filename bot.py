import os
import asyncio
import logging
import re
import json
import requests
import socket
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, filters, ContextTypes
from datetime import datetime
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import whois
from bs4 import BeautifulSoup
import hashlib

# Logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    handlers=[logging.FileHandler('hunter.log'), logging.StreamHandler()]
)

class OSINTHunterV35:
    def __init__(self):
        # التوكن صريح هنا
        self.token = "8246905590:AAHdlEfGb_bGtHMVrXDjs9X5ErklquDlU9Q"
        self.app = Application.builder().token(self.token).build()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.setup_handlers()

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        keyboard = [[InlineKeyboardButton("🚀 ابدأ الصيد", callback_data="hunt")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        msg = await update.message.reply_text(msg, parse_mode='Markdown', reply_markup=reply_markup)

    # 🔥 IP OSINT الأقوى في العالم 🔥
    def god_ip_recon(self, ip):
        result = f"**🌐 GOD IP RECON: `{ip}`** 🕵️‍♂️\n\n"
        
        # 10 IP APIs حقيقية
        apis = [
            f"http://ip-api.com/json/{ip}",
            f"https://ipinfo.io/{ip}/json",
            f"https://ipapi.co/{ip}/json/",
            f"https://api.ipgeolocation.io/ipgeo?apiKey=demo&ip={ip}",
            f"https://ipwhois.app/json/{ip}",
            f"https://extreme-ip-lookup.com/api/?ip={ip}"
        ]
        
        geo_consensus = {"country": [], "isp": [], "city": [], "org": []}
        for api_url in apis:
            try:
                resp = self.session.get(api_url, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    # جمع البيانات
                    geo_consensus["country"].append(data.get("country") or data.get("country_name"))
                    geo_consensus["isp"].append(data.get("isp") or data.get("org"))
                    geo_consensus["city"].append(data.get("city"))
                    geo_consensus["org"].append(data.get("org") or data.get("as"))
            except:
                continue
        
        # عرض النتائج المتوافقة
        result += f"🌍 **البلد:** `{geo_consensus['country'][0] if geo_consensus['country'] else '??'}`\n"
        result += f"🏢 **ISP:** `{geo_consensus['isp'][0] if geo_consensus['isp'] else '??'}`\n"
        result += f"📍 **المدينة:** `{geo_consensus['city'][0] if geo_consensus['city'] else '??'}`\n"
        result += f"🏛️ **المنظمة:** `{geo_consensus['org'][0] if geo_consensus['org'] else '??'}`\n\n"
        
        # Port Scan حقيقي
        result += self.fast_port_scan(ip)
        
        # Reverse DNS
        result += self.reverse_dns(ip)
        
        return result

    def fast_port_scan(self, ip):
        """مسح سريع للمنافذ الشائعة"""
        critical_ports = [21,22,23,25,53,80,443,993,995,1433,3306,3389,5432,8080]
        open_ports = []
        
        result = "**🔌 PORT SCAN (سريع):**\n"
        for port in critical_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        if open_ports:
            port_names = {21:'FTP',22:'SSH',80:'HTTP',443:'HTTPS',3389:'RDP',3306:'MySQL',8080:'HTTP-ALT'}
            result += f"✅ **مفتوحة ({len(open_ports)}):** `{open_ports}`\n"
            result += f"🎯 **الخدمات:** `{[port_names.get(p, f'Port-{p}') for p in open_ports]}`\n"
        else:
            result += "🔒 **جميع المنافذ آمنة** ✅\n"
        return result + "\n"

    def reverse_dns(self, ip):
        """Reverse DNS Lookup"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return f"🔄 **Reverse DNS:** `{hostname}`\n\n"
        except:
            return f"🔄 **Reverse DNS:** غير متوفر\n\n"

    # 📱 Phone OSINT
    def phone_hunter(self, phone):
        try:
            parsed = phonenumbers.parse(phone)
            info = {
                "دولي": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "البلد": geocoder.description_for_number(parsed, "ar"),
                "الشبكة": carrier.name_for_number(parsed, "ar") or "غير معروف",
                "الموقع": geocoder.description_for_number(parsed, "en"),
                "المنطقة": str(timezone.time_zones_for_number(parsed))
            }
            return f"**📱 PHONE HUNTER: `{phone}`**\n\n" + "\n".join([f"**{k}:** `{v}`" for k,v in info.items()])
        except:
            return f"**📱 PHONE: `{phone}`** ❌ رقم غير صالح"

    # 👥 Social Media Hunter
    async def social_hunter(self, username):
        platforms = {
            "Twitter": f"https://twitter.com/{username}",
            "Instagram": f"https://instagram.com/{username}",
            "Facebook": f"https://facebook.com/{username}",
            "GitHub": f"https://github.com/{username}",
            "LinkedIn": f"https://linkedin.com/in/{username}",
            "TikTok": f"https://tiktok.com/@{username}"
        }
        
        result = "**🌐 SOCIAL HUNTER:**\n\n"
        for platform, url in platforms.items():
            try:
                resp = self.session.head(url, timeout=4, allow_redirects=True)
                status = "✅ موجود" if resp.status_code < 400 else "❌ غير موجود"
                result += f"**{platform}:** [{url}]({url}) `{status}`\n"
            except:
                result += f"**{platform}:** `{url}` ⚠️ خطأ\n"
        return result

    async def handle_target(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        target = update.message.text.strip()
        await update.message.reply_chat_action("typing")
        
        # تحليل الـ target
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            result = self.god_ip_recon(target)
        elif re.match(r'^\+?\d{10,15}$', target.replace(' ', '').replace('-', '')):
            result = self.phone_hunter(target)
        elif '@' in target:
            result = await self.email_hunter(target)
        else:
            result = await self.social_hunter(target)
        
        await update.message.reply_text(result, parse_mode='Markdown', disable_web_page_preview=True)

    async def email_hunter(self, email):
        domain = email.split('@')[1]
        result = f"**✉️ EMAIL HUNTER: `{email}`**\n\n"
        
        try:
            # WHOIS
            w = whois.whois(domain)
            result += f"**🏢 WHOIS {domain}:**\n"
            result += f"`{w.registrar}`\n"
            if w.creation_date:
                result += f"`تاريخ الإنشاء: {w.creation_date}`\n"
        except:
            result += "**🏢 WHOIS:** غير متوفر\n"
        
        return result

    def setup_handlers(self):
        self.app.add_handler(CommandHandler("start", self.start))
        self.app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_target))
        self.app.add_handler(CallbackQueryHandler(lambda u,c: u.callback_query.answer()))

    def run(self):
        print("🏴‍☠️ OSINT HUNTER v3.5 LIVE 🏴‍☠️")
        print("🔥 جاهز للصيد! 🔥")
        self.app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    hunter = OSINTHunterV35()
    hunter.run()
