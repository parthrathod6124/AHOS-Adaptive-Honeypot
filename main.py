from orchestrator.fingerprinter import PassiveFingerprinter
from config import HONEYPOT_PORTS
from rich.console import Console
from pyfiglet import figlet_format

console = Console()

def banner():
    console.print(figlet_format("AHOS", font="slant"), style="bold red")
    console.print("[bold yellow]Adaptive Honeypot Orchestration System[/bold yellow]")
    console.print("[dim]Phase 1 — Passive TCP Fingerprinting Engine[/dim]\n")

if __name__ == "__main__":
    banner()
    fp = PassiveFingerprinter(interface="eth0")
    fp.start(ports=HONEYPOT_PORTS)
