"""
Automated Cloud-Aware Memory Forensics Platform
Main Launcher Script
"""
import sys
import uvicorn
from app.config import HOST, PORT, APP_TITLE, APP_VERSION

def banner():
    print("=" * 70)
    print(f" {APP_TITLE} [{APP_VERSION}]")
    print(" Final Year B.Tech CSE Cyber Security Academic Project")
    print("=" * 70)
    print(" [*] Technology Stack : Python 3.14+, FastAPI, Volatility 3, SQLite")
    print(f" [*] Local Server     : http://{HOST}:{PORT}")
    print(f" [*] Swagger API Docs : http://{HOST}:{PORT}/docs")
    print(f" [*] ReDoc Reference  : http://{HOST}:{PORT}/redoc")
    print(" [*] Active Phase     : PHASE 1 (Project Foundation & Dashboard)")
    print("=" * 70)
    print(" [i] Press Ctrl+C in terminal to stop server.\n")

if __name__ == "__main__":
    banner()
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=True)
