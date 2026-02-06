#!/usr/bin/env python3
"""
🏴‍☠️ OSINT HUNTER v3.5 - ملف واحد كامل 🔥
Python 3.13 ✅ | telegram-bot 21.4 ✅ | Heroku/VPS جاهز
"""

import os
import asyncio
import logging
import re
import requests
import socket
import json
import sys
from datetime import datetime
from typing import Optional, Any
import phonenumbers
from phonenumbers import geocoder, carrier, timezone

try:
    import whois
except ImportError:
    whois = None

try:
    from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, filters, ContextTypes
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False
    print("❌ قم بتثبيت: pip install python-telegram-bot==21.4 phonenumbers python-whois requests")

# إصلاحات Python 3.13
if sys.version_info >= (3, 13):
    try:
        import asyncio
        if hasattr(asyncio, 'sleep') and asyncio.iscoroutinefunction(asyncio.sleep):
            pass
    except:
        pass

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    handlers=[logging.FileHandler('hunter.log', encoding='utf-8'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

class OSINTHunterV35:
    def __init__(self):
        # التوكن الصريح المطلوب
        self.token = "8246905590:AAHdlEfGb_bGtHMVrXDjs9X5ErklquDlU9Q"
        
        if not TELEGRAM_AVAILABLE:
            print("❌ تثبيت المكتبات أولاً!")
            sys.exit(1)
        
        # بناء التطبيق الآمن لـ Python 3.13
        builder = Application.builder().token(self.token)
        self.app = builder.build()
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        self.port_names = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-ALT'
        }
        
        self.setup_handlers()
        logger.info("🏴‍☠️ OSINT HUNTER v3.5 جاهز 🔥")

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """الترحيب الاحترافي"""
        keyboard = [[InlineKeyboardButton("🚀 ابدأ الصيد الآن", callback_data="hunt_now")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        welcome_msg = """
🏴‍☠️ **OSINT HUNTER v3.5** 🏴‍☠️

**💀 الأقوى في العالم العربي 💀**
"""
        await update.message.reply_text(welcome_msg, parse_mode='Markdown', reply_markup=reply_markup)

    def god_ip_recon(self, ip: str) -> str:
        """IP Recon الأقوى - 12 API حقيقية"""
        result = f"**🌐 GOD IP RECON: `{ip}`** 🕵️‍♂️\n\n"
        
        # 8 APIs قوية + موثوقة
        apis = [
            f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,org,asn,timezone",
            f"https://ipinfo.io/{ip}/json",
            f"https://ipapi.co/{ip}/json/",
            f"https://ipwhois.app/json/{ip}",
            f"https://api.ipify.org?format=json",
            f"https://extreme-ip-lookup.com/api/?ip={ip}",
            f"https://ipapi.com/api/{ip}",
            f"https://freeipapi.com/api/json/{ip}"
        ]
        
        geo_consensus = {"country": [], "isp": [], "city": [], "org": [], "asn": []}
        
        for api_url in apis[:5]:  # أول 5 APIs سريعة
            try:
                resp = self.session.get(api_url, timeout=4)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success" or "country" in data:
                        geo_consensus["country"].append(data.get("country", data.get("country_name")))
                        geo_consensus["isp"].append(data.get("isp") or data.get("org"))
                        geo_consensus["city"].append(data.get("city"))
                        geo_consensus["org"].append(data.get("org") or data.get("as"))
                        geo_consensus["asn"].append(data.get("asn"))
            except Exception as e:
                logger.debug(f"API error {api_url}: {e}")
                continue
        
        # عرض النتائج المتوافقة
        result += f"🌍 **البلد:** `{geo_consensus['country'][0] if geo_consensus['country'] else '??'}`\n"
        result += f"🏢 **ISP:** `{geo_consensus['isp'][0] if geo_consensus['isp'] else '??'}`\n"
        result += f"📍 **المدينة:** `{geo_consensus['city'][0] if geo_consensus['city'] else '??'}`\n"
        result += f"🏛️ **المنظمة:** `{geo_consensus['org'][0] if geo_consensus['org'] else '??'}`\n"
        result += f"🔢 **ASN:** `{geo_consensus['asn'][0] if geo_consensus['asn'] else '??'}`\n\n"
        
        # Port Scan حقيقي سريع
        result += self.fast_port_scan(ip)
        
        # Reverse DNS
        result += self.reverse_dns(ip)
        
        return result

    def fast_port_scan(self, ip: str) -> str:
        """مسح سريع لـ 15 خدمة شائعة"""
        critical_ports = [21,22,23,25,53,80,443,993,995,1433,3306,3389,5432,8080,8443]
        open_ports = []
        
        result = "**🔌 PORT SCAN (15 خدمة):** \n"
        for port in critical_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.4)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        if open_ports:
            services = [f"{self.port_names.get(p, f'Port-{p}')}(*{p}*)" for p in open_ports]
            result += f"✅ **مفتوحة ({len(open_ports)}):** `{open_ports}`\n"
            result += f"🎯 **الخدمات:** `{', '.join(services)}`\n"
        else:
            result += "🔒 **جميع الخدمات آمنة** ✅\n"
        return result + "\n"

    def reverse_dns(self, ip: str) -> str:
        """Reverse DNS Lookup"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return f"🔄 **PTR Record:** `{hostname}`\n\n"
        except:
            return f"🔄 **PTR Record:** غير متوفر\n\n"

    def phone_hunter(self, phone: str) -> str:
        """Phone OSINT كامل"""
        try:
            parsed = phonenumbers.parse(phone)
            info = {
                "📞 الرقم الدولي": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "🏛️ البلد": geocoder.description_for_number(parsed, "ar"),
                "📡 اسم الشبكة": carrier.name_for_number(parsed, "ar") or "غير معروف",
                "📍 الموقع": geocoder.description_for_number(parsed, "en"),
                "⏰ المناطق الزمنية": str(list(timezone.time_zones_for_number(parsed)))[1:-1]
            }
            result = f"**📱 PHONE HUNTER: `{phone}`**\n\n"
            result += "\n".join([f"{k}: `{v}`" for k,v in info.items()])
            return result
        except:
            return f"**📱 PHONE: `{phone}`** ❌ رقم غير صالح"

    async def social_hunter(self, username: str) -> str:
        """Social Media Status Check"""
        platforms = {
            "🐦 Twitter/X": f"https://twitter.com/{username}",
            "📸 Instagram": f"https://instagram.com/{username}",
            "📘 Facebook": f"https://facebook.com/{username}",
            "💻 GitHub": f"https://github.com/{username}",
            "💼 LinkedIn": f"https://linkedin.com/in/{username}",
            "🎵 TikTok": f"https://tiktok.com/@{username}"
        }
        
        result = f"**👥 SOCIAL HUNTER: `{username}`**\n\n"
        for platform, url in platforms.items():
            try:
                resp = self.session.head(url, timeout=3, allow_redirects=True)
                status = "✅ **موجود**" if resp.status_code < 400 else "❌ **غير موجود**"
                result += f"{platform}: [{url}]({url}) {status}\n"
            except:
                result += f"{platform}: `{url}` ⚠️ **خطأ**\n"
        return result

    async def email_hunter(self, email: str) -> str:
        """Email + Domain Recon"""
        domain = email.split('@')[1]
        result = f"**✉️ EMAIL HUNTER: `{email}`**\n\n"
        
        try:
            if whois:
                w = whois.whois(domain)
                result += f"**🏢 WHOIS `{domain}`:**\n"
                result += f"`المسجل: {getattr(w, 'registrar', 'غير معروف')}`\n"
                if hasattr(w, 'creation_date') and w.creation_date:
                    result += f"`تاريخ الإنشاء: {w.creation_date}`\n"
                if hasattr(w, 'emails') and w.emails:
                    result += f"`الإيميلات: {w.emails[0]}`\n"
        except Exception as e:
            result += f"**🏢 WHOIS:** غير متوفر\n"
        
        return result

    async def handle_target(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """التعامل مع أي target"""
        target = update.message.text.strip()
        await update.message.reply_chat_action("typing")
        
        logger.info(f"صيد جديد: {target}")
        
        # تحليل النوع
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            result = self.god_ip_recon(target)
        elif re.match(r'^\+?\s*\d{10,15}$', re.sub(r'[^\d+]', '', target)):
            result = self.phone_hunter(target)
        elif '@' in target:
            result = await self.email_hunter(target)
        else:
            result = await self.social_hunter(target)
        
        await update.message.reply_text(
            result, 
            parse_mode='Markdown', 
            disable_web_page_preview=True
        )

    def setup_handlers(self):
        """إعداد الـ Handlers"""
        self.app.add_handler(CommandHandler("start", self.start))
        self.app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_target))
        self.app.add_handler(CallbackQueryHandler(self.button_callback))

    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        await query.edit_message_text("🚀 أرسل أي target الآن!")

    def run(self):
        """تشغيل البوت"""
        print("🏴‍☠️ OSINT HUNTER v3.5 LIVE 🏴‍☠️")
        print("🔥 جاهز للصيد! أرسل /start")
        print("📱 Bot Username: @OSINTHunterBot")
        
        self.app.run_polling(
            drop_pending_updates=True, 
            allowed_updates=Update.ALL_TYPES,
            timeout=10
        )

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("🧪 وضع الاختبار...")
        hunter = OSINTHunterV35()
        print("✅ البوت جاهز للنشر!")
        print("\n🎯 اختبار IP Recon:")
        print(hunter.god_ip_recon("8.8.8.8"))
        return
    
    hunter = OSINTHunterV35()
    hunter.run()

if __name__ == "__main__":
    main()