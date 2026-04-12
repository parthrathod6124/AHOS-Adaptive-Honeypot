"""
AHOS - Adaptation Engine
Reads attacker profiles from Redis and dynamically
changes honeypot behavior to maximize engagement.
"""

import redis
import json
import time
import subprocess
from datetime import datetime

rd = redis.Redis(host='localhost', port=6379, decode_responses=True)

# ── Adaptation Rules ───────────────────────────────────
ADAPTATION_RULES = {
    "nmap_syn_scan": {
        "action":      "slow_responses",
        "banner":      "SSH-2.0-OpenSSH_7.4",
        "delay_ms":    500,
        "description": "Slow down responses to appear as real SSH server"
    },
    "masscan": {
        "action":      "fake_open_ports",
        "banner":      "220 FTP Server Ready",
        "delay_ms":    0,
        "description": "Instantly respond to mass scanner"
    },
    "linux_manual": {
        "action":      "full_engagement",
        "banner":      "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        "delay_ms":    100,
        "description": "Full engagement - human attacker detected"
    },
    "windows_manual": {
        "action":      "full_engagement",
        "banner":      "220 Microsoft FTP Service",
        "delay_ms":    150,
        "description": "Full engagement - Windows user detected"
    },
    "shodan_crawler": {
        "action":      "minimal_response",
        "banner":      "HTTP/1.1 200 OK",
        "delay_ms":    0,
        "description": "Minimal response to Shodan crawler"
    },
    "unknown_scanner": {
        "action":      "fake_open_ports",
        "banner":      "220 Service Ready",
        "delay_ms":    200,
        "description": "Generic response to unknown scanner"
    },
}


class AdaptationEngine:

    def __init__(self):
        self.adapted = {}   # ip -> adaptation applied

    def _log(self, msg):
        ts = datetime.utcnow().strftime("%H:%M:%S")
        print(f"[ADAPT {ts}] {msg}")

    def _apply_adaptation(self, profile: dict):
        """Apply adaptation rules based on attacker profile."""
        src_ip = profile.get("src_ip", "unknown")
        tool   = profile.get("detected_tool", "unknown_scanner")
        threat = profile.get("threat_level", "low")
        human  = profile.get("is_human", False)

        rule = ADAPTATION_RULES.get(tool, ADAPTATION_RULES["unknown_scanner"])

        self._log(f"Adapting for {src_ip} | Tool: {tool} | Threat: {threat}")
        self._log(f"Action: {rule['action']}")
        self._log(f"Banner: {rule['banner']}")
        self._log(f"Delay:  {rule['delay_ms']}ms")
        self._log(f"Reason: {rule['description']}\n")

        # Store adaptation in Redis for dashboard
        rd.hset(f"adaptation:{src_ip}", mapping={
            "tool":        tool,
            "action":      rule["action"],
            "banner":      rule["banner"],
            "delay_ms":    str(rule["delay_ms"]),
            "threat":      threat,
            "is_human":    str(human),
            "adapted_at":  datetime.utcnow().isoformat()
        })

        # Publish adaptation event
        rd.publish("adaptation_applied", json.dumps({
            "src_ip":  src_ip,
            "tool":    tool,
            "action":  rule["action"],
            "banner":  rule["banner"],
            "threat":  threat,
        }))

        self.adapted[src_ip] = rule
        return rule

    def _handle_human(self, profile: dict, rule: dict):
        """Extra steps for human attackers - maximum deception."""
        src_ip = profile.get("src_ip")
        self._log(f"⚠️  HUMAN ATTACKER DETECTED: {src_ip}")
        self._log(f"Switching to full engagement mode...")

        # Store high-priority alert
        rd.lpush("human_alerts", json.dumps({
            "src_ip":    src_ip,
            "tool":      profile.get("detected_tool"),
            "timestamp": datetime.utcnow().isoformat(),
            "priority":  "HIGH"
        }))
        self._log(f"Alert stored in Redis for dashboard\n")

    def start(self):
        try:
            pubsub = rd.pubsub()
            pubsub.subscribe("attacker_detected")
            self._log("Adaptation Engine active - waiting for profiles...\n")

            for message in pubsub.listen():
                if message["type"] != "message":
                    continue
                try:
                    profile = json.loads(message["data"])
                    src_ip  = profile.get("src_ip")
                    if src_ip in self.adapted:
                        continue
                    rule = self._apply_adaptation(profile)
                    if profile.get("is_human"):
                        self._handle_human(profile, rule)
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            print(f"[ADAPT ERROR] {e}")
            import traceback
            traceback.print_exc()