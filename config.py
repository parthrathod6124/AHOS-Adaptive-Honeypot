# AHOS - Global Configuration
# Kali Linux VMware Environment

NETWORK_INTERFACE = "any"        # VMware default interface

REDIS_HOST = "localhost"
REDIS_PORT = 6379
LOG_DIR    = "./logs"

HONEYPOT_PORTS = {
    "ssh":  2222,
    "http": 8080,
    "ftp":  2121,
    "smb":  4445,
}

SCANNER_TIMING_THRESHOLD_MS = 100
BRUTE_FORCE_ATTEMPT_LIMIT   = 5
