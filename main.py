"""
AHOS - Adaptive Honeypot Orchestration System
Run: sudo python main.py
"""

import threading
from orchestrator.fingerprinter import PassiveFingerprinter
from orchestrator.spawner import HoneypotSpawner
from config import HONEYPOT_PORTS
from rich.console import Console
from pyfiglet import figlet_format

console = Console()

def banner():
    console.print(figlet_format("AHOS", font="slant"), style="bold red")
    console.print("[bold yellow]Adaptive Honeypot Orchestration System[/bold yellow]")
    console.print("[dim]Phase 1 + 2 — Fingerprinter + Honeypot Spawner[/dim]\n")

if __name__ == "__main__":
    banner()

    # Phase 2 — spawner runs in background thread
    spawner = HoneypotSpawner()
    t = threading.Thread(target=spawner.start, daemon=True)
    t.start()

    # Phase 1 — fingerprinter runs in main thread
    fp = PassiveFingerprinter(interface="eth0")
    fp.start(ports=HONEYPOT_PORTS)