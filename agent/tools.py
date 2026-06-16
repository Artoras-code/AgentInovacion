import os
import requests
from dotenv import load_dotenv
import requests

load_dotenv(dotenv_path="config/.env")

def check_ip_virustotal(ip_address: str) -> str:
    """
    Consulta la API de VirusTotal para analizar una dirección IP.
    Retorna un resumen de los motores que la detectaron como maliciosa.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    
    if not api_key or api_key == "tu_clave_de_virustotal_aqui":
        return "Error: La API Key de VirusTotal no está configurada correctamente en el archivo .env."

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status() # Lanza un error si la petición falla
        
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        
        # Sintetizamos la respuesta para que el agente la entienda fácilmente
        resultado = (
            f"Análisis de VirusTotal para la IP {ip_address}:\n"
            f"- Maliciosos: {malicious}\n"
            f"- Sospechosos: {suspicious}\n"
            f"- Inofensivos: {harmless}\n"
            f"- No detectados: {undetected}\n"
        )
        
        if malicious > 0:
            resultado += "\n¡ALERTA! Esta IP ha sido reportada como maliciosa."
            
        return resultado

    except requests.exceptions.RequestException as e:
        return f"Error al consultar VirusTotal: {str(e)}"

def search_cve(cve_id: str) -> str:
    """
    Busca información detallada sobre un CVE específico usando la API oficial de MITRE.
    """
    try:
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            try:
                # Navegamos por el JSON de Mitre para extraer la descripción oficial
                summary = data["containers"]["cna"]["descriptions"][0]["value"]
                return f"Descripción oficial de {cve_id}: {summary}"
            except (KeyError, IndexError):
                return f"El {cve_id} existe en MITRE, pero no se pudo extraer el texto exacto."
        else:
            return f"Fallo al consultar MITRE (HTTP {response.status_code})."
            
    except Exception as e:
        return f"Error interno en la herramienta de CVEs: {str(e)}"

def check_domain_virustotal(domain: str) -> str:
    """
    Consulta VirusTotal para analizar un dominio sospechoso.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return "Error: API Key de VirusTotal no configurada."

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"accept": "application/json", "x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']

        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)

        resultado = (
            f"Análisis de VirusTotal para el dominio {domain}:\n"
            f"- Maliciosos: {malicious}\n"
            f"- Sospechosos: {suspicious}\n"
            f"- Inofensivos: {harmless}\n"
        )
        if malicious > 0:
            resultado += "\n¡ALERTA! Este dominio ha sido reportado como malicioso."
        return resultado

    except requests.exceptions.RequestException as e:
        return f"Error al consultar VirusTotal para dominio: {str(e)}"


def analyze_log_lines(log_text: str) -> str:
    """
    Analiza líneas de log en busca de patrones sospechosos comunes.
    """
    import re

    patterns = {
        "SQL Injection":     r"(union\s+select|drop\s+table|insert\s+into|'--|\bor\b\s+1=1)",
        "Path Traversal":    r"\.\./|\.\.\\",
        "XSS":               r"<script|javascript:|onerror=|onload=",
        "Escaneo de puertos":r"(nmap|masscan|SYN scan)",
        "Log4Shell":         r"\$\{jndi:",
        "Shell reversa":     r"(bash -i|nc -e|/bin/sh)",
        "Fuerza bruta":      r"(failed password|authentication failure|invalid user)",
    }

    alertas = []
    lines = log_text.strip().split("\n")

    for i, line in enumerate(lines, 1):
        for nombre, patron in patterns.items():
            if re.search(patron, line, re.IGNORECASE):
                alertas.append(f"Línea {i} [{nombre}]: {line.strip()}")

    if alertas:
        return "⚠️ Patrones sospechosos detectados:\n" + "\n".join(alertas)
    return "✅ No se detectaron patrones sospechosos en los logs."


def check_ip_shodan(ip_address: str) -> str:
    """
    Consulta Shodan para obtener puertos abiertos y servicios de una IP.
    """
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return "Error: API Key de Shodan no configurada."

    try:
        url = f"https://api.shodan.io/shodan/host/{ip_address}?key={api_key}"
        response = requests.get(url, timeout=10)

        if response.status_code == 404:
            return f"Shodan no tiene datos sobre la IP {ip_address}."

        response.raise_for_status()
        data = response.json()

        puertos = data.get("ports", [])
        org = data.get("org", "Desconocida")
        country = data.get("country_name", "Desconocido")
        hostnames = data.get("hostnames", [])
        vulns = list(data.get("vulns", {}).keys())

        resultado = (
            f"Shodan - IP: {ip_address}\n"
            f"- Organización: {org}\n"
            f"- País: {country}\n"
            f"- Hostnames: {', '.join(hostnames) if hostnames else 'ninguno'}\n"
            f"- Puertos abiertos: {puertos}\n"
        )
        if vulns:
            resultado += f"- ⚠️ CVEs asociados: {', '.join(vulns)}\n"

        return resultado

    except requests.exceptions.RequestException as e:
        return f"Error al consultar Shodan: {str(e)}"