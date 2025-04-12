import sqlite3
import requests
from flask import Flask, request, render_template, redirect, url_for

app = Flask(__name__)

# Liste des pays autorisés
allowed_countries = ['IL', 'BY', 'MD', 'RU']  # Israël, Biélorussie, Moldavie, Russie

@app.route('/')
def home():
    user_agent = request.headers.get('User-Agent')
    user_ip = request.remote_addr  # récupère l'IP de l'utilisateur

    # Vérification du User-Agent personnalisé
    if user_agent != 'trhacknontryer':
        return "Veuillez utiliser un User-Agent valide pour participer au challenge.", 400

    # GeoIP - exemple avec une API publique (ipinfo.io)
    geo_info = requests.get(f'http://ipinfo.io/{user_ip}/json').json()
    country = geo_info.get('country')

    # Restriction géographique (Israël, Biélorussie, Moldavie, Russie)
    if country not in allowed_countries:
        return "Accès interdit à partir de votre pays.", 403

    # Stocker les logs (IP, User-Agent, Heure, Géolocalisation)
    log_access(user_ip, user_agent, geo_info)

    return render_template("challenge.html")

def log_access(ip, user_agent, geo_info):
    # Enregistrez les informations dans un fichier log ou une base de données
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
    user_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    geo_info = requests.get(f'http://ipinfo.io/{user_ip}/json').json()
    log_success(user_ip, user_agent, geo_info)
    return "Félicitations ! Vous avez remporté le flag."

def log_success(ip, user_agent, geo_info):
    # Enregistrez le succès du challenge
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
    secret_key = "VOTRE_SECRET_KEY"  # Remplacez par votre clé secrète reCAPTCHA
    payload = {'response': captcha_response, 'secret': secret_key}
    r = requests.post("https://www.google.com/recaptcha/api/siteverify", data=payload)
    result = r.json()

    if result['success']:
        return redirect(url_for('reward'))
    else:
        return "Erreur CAPTCHA. Veuillez réessayer.", 400

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0)
