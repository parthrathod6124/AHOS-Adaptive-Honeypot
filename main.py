"""
AHOS - Adaptive Honeypot Orchestration System
Run: sudo venv/bin/python main.py
"""

import threading
from orchestrator.fingerprinter    import PassiveFingerprinter
from orchestrator.spawner          import HoneypotSpawner
from orchestrator.adaptation_engine import AdaptationEngine
from config import HONEYPOT_PORTS
from rich.console import Console
from pyfiglet import figlet_format

console = Console()

def banner():
    console.print(figlet_format("AHOS", font="slant"), style="bold red")
    console.print("[bold yellow]Adaptive Honeypot Orchestration System[/bold yellow]")
    console.print("[dim]Phase 1+2+3 — Fingerprinter + Spawner + Adaptation[/dim]\n")

if __name__ == "__main__":
    banner()

    # Phase 2 — spawner
    spawner = HoneypotSpawner()
    t1 = threading.Thread(target=spawner.start, daemon=True)
    t1.start()

    # Phase 3 — adaptation engine
    engine = AdaptationEngine()
    t2 = threading.Thread(target=engine.start, daemon=True)
    t2.start()

    # Phase 1 — fingerprinter (main thread)
    fp = PassiveFingerprinter(interface="eth0")
    fp.start(ports=HONEYPOT_PORTS)