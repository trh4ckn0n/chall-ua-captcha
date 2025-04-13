import sqlite3
import requests
from flask import Flask, request, render_template, redirect, url_for
import os

app = Flask(__name__)

# Liste des pays autorisés
allowed_countries = ['IL', 'BY', 'MD', 'RU']  # Israël, Biélorussie, Moldavie, Russie

@app.route('/')
def home():
    user_agent = request.headers.get('User-Agent', '').lower()
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

    # Vérification du User-Agent personnalisé
    if 'trhacknontryer' not in user_agent:
        return "Veuillez utiliser un User-Agent valide pour participer au challenge.", 400

    # GeoIP
    geo_info = requests.get(f'https://ipinfo.io/{user_ip}/json').json()
    country = geo_info.get('country', '')

    print(f"[DEBUG] IP: {user_ip}, Country: {country}, UA: {user_agent}")

    # Restriction géographique
    if country not in allowed_countries:
        return "Accès interdit à partir de votre pays.", 403

    # Stocker les logs
    log_access(user_ip, user_agent, geo_info)

    return render_template("challenge.html")

def log_access(ip, user_agent, geo_info):
    conn = sqlite3.connect('access_log.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS access_log (
            id INTEGER PRIMARY KEY,
            ip TEXT,
            user_agent TEXT,
            country TEXT,
            city TEXT,
            loc TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('INSERT INTO access_log (ip, user_agent, country, city, loc) VALUES (?, ?, ?, ?, ?)',
              (ip, user_agent, geo_info.get('country', 'Unknown'), geo_info.get('city', 'Unknown'), geo_info.get('loc', 'Unknown')))
    conn.commit()
    conn.close()

@app.route('/reward')
def reward():
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    user_agent = request.headers.get('User-Agent', '').lower()
    geo_info = requests.get(f'https://ipinfo.io/{user_ip}/json').json()
    log_success(user_ip, user_agent, geo_info)
    return f"Félicitations {user_ip} you are connected from {geo_info.get('country')}! Vous avez remporté le flag."

def log_success(ip, user_agent, geo_info):
    conn = sqlite3.connect('success_log.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS success_log (
            id INTEGER PRIMARY KEY,
            ip TEXT,
            user_agent TEXT,
            country TEXT,
            city TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('INSERT INTO success_log (ip, user_agent, country, city) VALUES (?, ?, ?, ?)',
              (ip, user_agent, geo_info.get('country', 'Unknown'), geo_info.get('city', 'Unknown')))
    conn.commit()
    conn.close()

@app.route('/verify', methods=['POST'])
def verify():
    captcha_response = request.form['g-recaptcha-response']
    secret_key = os.getenv("RECAPTCHA_SECRET_KEY", "6LcRMhYrAAAAAAkk400Ie-3_QuAYYfYbkd6kcGwM")
    payload = {'response': captcha_response, 'secret': secret_key}
    r = requests.post("https://www.google.com/recaptcha/api/siteverify", data=payload)
    result = r.json()

    if result['success']:
        return redirect(url_for('reward'))
    else:
        return "Erreur CAPTCHA. Veuillez réessayer.", 400

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0")
