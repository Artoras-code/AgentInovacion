import os
import json
import re
from groq import Groq
from dotenv import load_dotenv
from agent.tools import check_ip_virustotal, check_domain_virustotal, check_ip_shodan, search_cve, analyze_log_lines

load_dotenv(dotenv_path="config/.env")

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

SYSTEM_PROMPT = """Eres un agente experto en ciberseguridad.

Tienes acceso a estas herramientas:
- check_ip_virustotal(ip_address): Analiza una IP en VirusTotal
- check_domain_virustotal(domain): Analiza un dominio en VirusTotal
- check_ip_shodan(ip_address): Obtiene puertos abiertos y servicios de una IP via Shodan
- search_cve(cve_id): Busca info oficial de un CVE en MITRE
- analyze_log_lines(log_text): Analiza líneas de log buscando patrones maliciosos

Si necesitas usar una herramienta, responde SOLO con este formato JSON, sin texto adicional antes ni después:
{"tool": "nombre_tool", "args": {"parametro": "valor"}}

Si necesitas usar múltiples herramientas, ponlas una por línea:
{"tool": "check_ip_virustotal", "args": {"ip_address": "1.2.3.4"}}
{"tool": "check_ip_shodan", "args": {"ip_address": "1.2.3.4"}}

Si ya tienes la información para responder, responde normalmente en español.
Nunca inventes datos de seguridad."""


def extract_tool_calls(reply: str) -> list:
    """Extrae tool calls del reply línea por línea."""
    tool_calls = []
    for line in reply.strip().split('\n'):
        line = line.strip()
        if line.startswith('{') and '"tool"' in line:
            try:
                tool_calls.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return tool_calls


def run_agent(query: str) -> str:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": query}
    ]

    try:
        for _ in range(5):
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=messages,
                temperature=0.2,
                max_tokens=1024,
            )

            reply = response.choices[0].message.content.strip()

            tool_calls = extract_tool_calls(reply)

            if tool_calls:
                results = []
                for tool_call in tool_calls:
                    try:
                        tool_name = tool_call.get("tool")
                        args = tool_call.get("args", {})

                        if tool_name == "check_ip_virustotal":
                            result = check_ip_virustotal(args.get("ip_address", ""))
                        elif tool_name == "check_domain_virustotal":
                            result = check_domain_virustotal(args.get("domain", ""))
                        elif tool_name == "check_ip_shodan":
                            result = check_ip_shodan(args.get("ip_address", ""))
                        elif tool_name == "search_cve":
                            result = search_cve(args.get("cve_id", ""))
                        elif tool_name == "analyze_log_lines":
                            result = analyze_log_lines(args.get("log_text", ""))
                        else:
                            result = "Herramienta no encontrada."

                        results.append(f"Resultado de {tool_name}: {result}")

                    except Exception as e:
                        results.append(f"Error ejecutando tool: {str(e)}")
                        continue

                messages.append({"role": "assistant", "content": reply})
                messages.append({"role": "user", "content": "\n\n".join(results)})

            else:
                return reply

        return "El agente no pudo completar la tarea en el número máximo de iteraciones."

    except Exception as e:
        return f"Error en el cerebro del agente: {str(e)}"