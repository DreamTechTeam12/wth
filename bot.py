from flask import Flask, jsonify, request, render_template_string
import requests
import random
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from bs4 import BeautifulSoup
import socket
import whois
from scapy.all import ARP, Ether, srp
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app)

scheduler = BackgroundScheduler()
scheduler.start()

sohbet_tarihi = []
user_data_list = []
yanitlar = {
    "Hava nasıl": ["Güzel!", "Biraz soğuk.", "Harika!"],
    "Nasılsın?": ["İyiyim, teşekkürler!", "Fena değil, sen nasılsın?"],
    "tilki.dev": ["Adam kral ya :3"],
    "dreamtech.dev": ["Yapımcım o :)"],
}

HTML_CONTENT = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/fork-awesome@1.2.0/css/fork-awesome.min.css">
    <title>DreamTech API Services</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        body {
            background-color: #1a1a1a;
            color: white;
            font-family: 'Poppins', sans-serif;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 800px;
            margin: auto;
            text-align: center;
            padding: 50px;
            background: #2E2E2E;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
        }
        button {
            background-color: #FFBF00;
            color: black;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1.2em;
        }
        button:hover {
            background-color: #FFC300;
        }
        #cookie-banner {
            position: fixed;
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(50, 50, 50, 0.9);
            padding: 20px;
            border-radius: 5px;
            display: none;
            z-index: 1000;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>DreamTech API Servisi</h1>
        <p>Bu site, çeşitli API'ler ile etkileşimde bulunmanızı sağlar.</p>
        <button onclick="window.location.href='/sohbet'">Sohbet API</button>
        <button onclick="window.location.href='/api/discorduser/YOUR_USER_ID'">Discord ID Lookup API</button>
        <button onclick="window.location.href=''">Ekonomi API</button>
        <button onclick="window.location.href='/api/recon?url=<URL>'">SEO Lookup</button>
        <button onclick="window.location.href=''">YAKINDA</button>

        <div id="cookie-banner">
            <p>Bu sitede güvenlik ve daha iyi hizmetler için Çerezler kullanılmaktadır. Kabul ediyor musunuz?</p>
            <button id="accept">Kabul Ediyorum</button>
            <button id="reject">Reddet</button>
        </div>
    </div>

    <script>
        document.addEventListener("DOMContentLoaded", function() {
            const banner = document.getElementById("cookie-banner");
            banner.style.display = "block";

            document.getElementById("accept").onclick = async function() { 
                document.cookie = "cookiesAccepted=true; path=/";

                const response = await fetch('/', {
                    method: 'POST',
                    body: JSON.stringify({ userAgent: navigator.userAgent }),
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });

                const data = await response.json();  
                banner.style.display = "none";
            };

            document.getElementById("reject").onclick = function() {
                document.cookie = "cookiesAccepted=false; path=/";
                banner.style.display = "none";
            };
        });
    </script>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        data = request.json
        user_agent = data.get('userAgent')
        screen_resolution = data.get('screenResolution')
        device_type = data.get('deviceType')
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)

        user_data = {
            'user_agent': user_agent,
            'screen_resolution': screen_resolution,
            'device_type': device_type,
            'ip_address': ip_address,
            'timestamp': datetime.now().isoformat()
        }
        
        user_data_list.append(user_data)
        return jsonify(user_data)

    return render_template_string(HTML_CONTENT)

@app.route('/soru-ekle', methods=['POST'])
def soru_ekle():
    soru = request.json.get('soru')
    if soru:
        sohbet_tarihi.append({'soru': soru})
        return jsonify({'message': 'Soru eklendi!'}), 201
    return jsonify({'error': 'Soru eksik!'}), 400

@app.route('/sohbet', methods=['GET'])
def cevap_ver():
    soru_param = request.args.get('soru')
    if soru_param:
        cevaplar = yanitlar.get(soru_param, ["Bu soruya yanıtım yok."])
        cevap = random.choice(cevaplar)
        return jsonify({'cevap': cevap}), 200
    return jsonify({'error': 'Soru yok!'}), 400

@app.route('/sorular', methods=['GET'])
def sorular():
    return jsonify(sohbet_tarihi), 200

# DISCORD LOOKUP API
TOKEN = 'YOUR_DISCORD_BOT_TOKEN'

def get_user_info(user_id):
    url = f'https://discord.com/api/v10/users/{user_id}'
    headers = {
        'Authorization': f'Bot {TOKEN}'
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        user_data = response.json()
        return {
            'username': user_data['username'],
            'discriminator': user_data['discriminator'],
            'id': user_data['id'],
            'avatar': user_data['avatar'],
            'locale': user_data.get('locale', 'Locale not available'),
            'verified': user_data.get('verified', False),
            'email': user_data.get('email', 'Email not available'),
            'created_at': datetime.fromtimestamp(int(user_data['id']) >> 22 + 1420070400000).isoformat()
        }
    else:
        return None

@app.route('/api/discorduser/<user_id>', methods=['GET'])
def user_info(user_id):
    user_info = get_user_info(user_id)
    
    if user_info:
        return jsonify(user_info), 200
    else:
        return jsonify({"error": "User not found or request failed."}), 404

# EKONOMI API
API_KEY = 'YOUR_API_KEY'
BASE_URL = 'https://api.exchangerate-api.com/v6/latest/'

@app.route('/api/rates/<base_currency>', methods=['GET'])
def get_exchange_rates(base_currency):
    url = f"{BASE_URL}{base_currency}"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        return jsonify(data)
    else:
        return jsonify({"error": "Para birimi bulunamadı veya API limiti aşıldı"}), 404

@app.route('/api/currencies', methods=['GET'])
def get_currencies():
    url = f"{BASE_URL}USD"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        return jsonify(data['rates'].keys())
    else:
        return jsonify({"error": "Para birimleri alınamadı"}), 500

# SEO API
def basic_recon(url):
    try:
        ip_address = socket.gethostbyname(url)
        response = requests.get(url)
        title = BeautifulSoup(response.text, 'html.parser').title.string if response.status_code == 200 else 'Başlık bulunamadı'
        server = response.headers.get('Server', 'Bilinmiyor')
        robots_txt = requests.get(f"{url}/robots.txt").text if requests.get(f"{url}/robots.txt").status_code == 200 else 'Robots.txt bulunamadı'

        return {
            "title": title,
            "ip_address": ip_address,
            "server": server,
            "cms": "Could Not Detect",
            "cloudflare": "Not Detected",
            "robots_file": robots_txt
        }
    except Exception as e:
        return {"error": str(e)}

def whois_lookup(url):
    try:
        return whois.whois(url)
    except Exception as e:
        return {"error": str(e)}

def geo_ip_lookup(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        return response.json() if response.status_code == 200 else {"error": "Geo-IP bilgisi alınamadı"}
    except Exception as e:
        return {"error": str(e)}

def dns_lookup(url):
    try:
        ip_address = socket.gethostbyname(url)
        dns_info = {
            "A": ip_address,
            "MX": "Gerekli bilgi yok",
            "NS": "Gerekli bilgi yok",
            "TXT": "Gerekli bilgi yok",
        }
        return dns_info
    except Exception as e:
        return {"error": str(e)}

@app.route('/api/recon', methods=['GET'])
def get_recon_data():
    url = request.args.get('url')
    
    if not url:
        return jsonify({"error": "URL parametresi gereklidir"}), 400
    
    recon_data = basic_recon(url)
    whois_data = whois_lookup(url)
    ip_address = recon_data.get("ip_address")
    geo_data = geo_ip_lookup(ip_address) if ip_address else {}
    dns_data = dns_lookup(url)

    response_data = {
        "Basic Info": recon_data,
        "WHOIS Lookup": whois_data,
        "Geo IP Lookup": geo_data,
        "DNS Lookup": dns_data
    }
    
    return jsonify(response_data)

# SALDIRI GÖRÜNTÜLEME API
attacks = [
    {"id": 1, "type": "DDoS", "country": "Türkiye", "timestamp": "2024-10-01T14:30:00"},
    {"id": 2, "type": "SQL Injection", "country": "Almanya", "timestamp": "2024-10-02T09:15:00"},
]

response_tips = {
    "DDoS": "Saldırıyı durdurmak için ağ trafiğinizi analiz edin ve güvenlik duvarı kurallarını güncelleyin.",
    "SQL Injection": "Veritabanı sorgularını parametreleştirin ve giriş doğrulama uygulayın."
}

@app.route('/api/attack-report', methods=['POST'])
def report_attack():
    attack_data = request.json
    attack_type = attack_data.get("type")
    country = attack_data.get("country")

    if attack_type in response_tips:
        attack_info = {
            "id": len(attacks) + 1,
            "type": attack_type,
            "country": country,
            "timestamp": datetime.now().isoformat(),
            "response": response_tips[attack_type]
        }
        attacks.append(attack_info)
        return jsonify(attack_info), 201
    else:
        return jsonify({"error": "Geçersiz saldırı türü"}), 400

@app.route('/api/attacks', methods=['GET'])
def get_attacks():
    return jsonify(attacks)

@app.route('/api/devices', methods=['GET'])
def get_devices():
    target_ip = request.args.get('ip')

    if not target_ip:
        return jsonify({"error": "IP parametresi gereklidir"}), 400

    arp = ARP(pdst=target_ip + '/24')
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether/arp
    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return jsonify(devices)

if __name__ == '__main__':
    app.run(port=5000)
