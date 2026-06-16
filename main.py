from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from agent.core import run_agent
from agent.tools import search_cve

load_dotenv(dotenv_path="config/.env")

app = FastAPI(
    title="Cyber Agent API", 
    description="API para el MVP del Agente de Ciberseguridad impulsado por Gemini"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class QueryRequest(BaseModel):
    query: str

@app.get("/")
def read_root():
    return {"status": "El servidor del Agente de Ciberseguridad está activo y listo."}

@app.post("/api/chat")
async def chat_with_agent(request: QueryRequest):
    """
    Recibe la tarea de seguridad, la procesa a través del agente y devuelve la respuesta.
    """
    respuesta_experta = run_agent(request.query)
    
    return {
        "query": request.query,
        "response": respuesta_experta,
        "tools_used": ["VirusTotal"] 
    }


@app.get("/api/test-cve/{cve_id}")
def test_cve_tool(cve_id: str):
    """Endpoint temporal para probar la herramienta de CVEs de forma directa"""
    resultado = search_cve(cve_id)
    return {
        "herramienta": "search_cve",
        "cve_buscado": cve_id,
        "resultado_crudo": resultado
    }