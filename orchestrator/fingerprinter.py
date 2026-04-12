"""
AHOS - Passive TCP/IP Stack Fingerprinter
"""

from scapy.all import sniff, IP, TCP
from dataclasses import dataclass, field
from datetime import datetime
import redis
import json

r = redis.Redis(host='localhost', port=6379, decode_responses=True)

HONEYPOT_PORTS = {
    "ssh":  2222,
    "http": 8080,
    "ftp":  2121,
    "smb":  4445,
}

TOOL_SIGNATURES = {
    "nmap_syn_scan": {
        "window": 1024,
        "ttl_min": 40, "ttl_max": 50,
        "options": "MSS,NOP,WScale,NOP,NOP,Timestamp,SACKPermitted,EOL",
    },
    "masscan": {
        "window": 1024,
        "ttl_min": 128, "ttl_max": 128,
        "options": "MSS",
    },
    "linux_manual": {
        "window": 29200,
        "ttl_min": 60, "ttl_max": 64,
        "options": "MSS,SACKPermitted,Timestamp,NOP,WScale",
    },
    "windows_manual": {
        "window": 65535,
        "ttl_min": 125, "ttl_max": 128,
        "options": "MSS,NOP,WScale,NOP,NOP,SACKPermitted",
    },
    "shodan_crawler": {
        "window": 1024,
        "ttl_min": 50, "ttl_max": 55,
        "options": "MSS,NOP,NOP,Timestamp,NOP,NOP,SACKPermitted",
    },
}

@dataclass
class AttackerProfile:
    src_ip:        str
    src_port:      int
    dst_port:      int
    window_size:   int
    ttl:           int
    tcp_options:   str
    detected_tool: str  = "unknown"
    threat_level:  str  = "low"
    is_human:      bool = False
    first_seen:    str  = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )

    def to_dict(self):
        return self.__dict__


class PassiveFingerprinter:

    def __init__(self, interface="eth0"):
        self.interface = interface
        self.attackers = {}

    def _parse_tcp_options(self, pkt):
        if not pkt.haslayer(TCP):
            return ""
        options = []
        for opt in pkt[TCP].options:
            if isinstance(opt, tuple):
                options.append(
                    opt[0] if isinstance(opt[0], str) else str(opt[0])
                )
            else:
                options.append(str(opt))
        return ",".join(options)

    def _match_tool(self, profile):
        best_match = "unknown_scanner"
        best_score = 0
        for tool_name, sig in TOOL_SIGNATURES.items():
            score = 0
            if profile.window_size == sig["window"]:
                score += 40
            if sig["ttl_min"] <= profile.ttl <= sig["ttl_max"]:
                score += 30
            if profile.tcp_options == sig["options"]:
                score += 30
            if score > best_score:
                best_score = score
                best_match = tool_name
        return best_match if best_score >= 40 else "unknown_scanner"

    def _assess_threat(self, tool):
        human_tools    = {"linux_manual", "windows_manual"}
        critical_tools = {"masscan", "nmap_syn_scan"}
        is_human       = tool in human_tools
        threat_level   = (
            "critical" if tool in critical_tools else
            "high"     if is_human               else
            "medium"   if tool == "shodan_crawler" else
            "low"
        )
        return threat_level, is_human

    def _publish(self, profile):
        r.hset(f"attacker:{profile.src_ip}", mapping={
            "profile":   json.dumps(profile.to_dict()),
            "tool":      profile.detected_tool,
            "threat":    profile.threat_level,
            "is_human":  str(profile.is_human),
            "last_seen": datetime.utcnow().isoformat()
        })
        r.publish("attacker_detected", json.dumps(profile.to_dict()))
        print(
            f"[FINGERPRINT] {profile.src_ip} → "
            f"Tool: {profile.detected_tool} | "
            f"Threat: {profile.threat_level} | "
            f"Human: {profile.is_human}"
        )

    def process_packet(self, pkt):
        print(f"[DEBUG] Packet received")
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            print(f"[DEBUG] No IP/TCP layer - skipping")
            return
        ports = set(HONEYPOT_PORTS.values())
        print(f"[DEBUG] dst={pkt[TCP].dport} src={pkt[TCP].sport} ports={ports}")
        if pkt[TCP].dport not in ports and pkt[TCP].sport not in ports:
            print(f"[DEBUG] Port not in honeypot ports - skipping")
            return
        print(f"[DEBUG] PASSED ALL FILTERS!")
        profile = AttackerProfile(
            src_ip      = pkt[IP].src,
            src_port    = pkt[TCP].sport,
            dst_port    = pkt[TCP].dport,
            window_size = pkt[TCP].window,
            ttl         = pkt[IP].ttl,
            tcp_options = self._parse_tcp_options(pkt),
        )
        profile.detected_tool                  = self._match_tool(profile)
        profile.threat_level, profile.is_human = self._assess_threat(
            profile.detected_tool
        )
        self.attackers[profile.src_ip] = profile
        self._publish(profile)

    def start(self, ports):
        from scapy.all import AsyncSniffer
        print(f"[*] Fingerprinter active on eth0 + lo")
        print(f"[*] Watching ports: {list(HONEYPOT_PORTS.values())}\n")

        s1 = AsyncSniffer(
            iface  = "eth0",
            filter = "tcp",
            prn    = self.process_packet,
            store  = False
        )
        s2 = AsyncSniffer(
            iface  = "lo",
            filter = "tcp",
            prn    = self.process_packet,
            store  = False
        )
        s1.start()
        s2.start()
        s1.join()