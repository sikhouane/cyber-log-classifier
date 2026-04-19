"""
classify_logs.py
Applique un ensemble de règles de détection sur un dataset de logs OpenSearch
et retourne un fichier JSON structuré avec les alertes et leur scoring.
"""

import json
import re
import argparse
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

#100% failure
HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR"}

#IPs/hostnames whitelistés
WHITELIST_IPS = set()
WHITELIST_HOSTNAMES = {"monitoring-01", "backup-01"}
WHITELIST_UA_PREFIXES = ("prometheus/", "grafana/", "zabbix/", "datadog/")

#brute force
BRUTE_FORCE_THRESHOLD = 10 #failures depuis même IP dans la fenêtre
BRUTE_FORCE_WINDOW_SEC = 300
CRED_STUFFING_USERNAMES = 5 #usernames distincts depuis même IP

#exfiltration
EXFIL_BYTES_THRESHOLD = 100_000   # bytes_sent au-delà duquel on suspecte une exfil

# Patterns d'attaques applicatives
SQLI_PATTERNS = [
    r"union\s+select", r"select\s+\*\s+from", r";\s*drop\s+table",
    r"--\s*$", r"or\s+1\s*=\s*1", r"sleep\s*\(", r"waitfor\s+delay",
    r"benchmark\s*\(", r"sqlmap", r"'\s*or\s+'", r"xp_cmdshell",
    r"information_schema", r"0x[0-9a-f]{4,}",
]
XSS_PATTERNS = [
    r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
    r"alert\s*\(", r"document\.cookie", r"<iframe", r"eval\s*\(",
]
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./", r"\.\.\\", r"/etc/passwd", r"/etc/shadow",
    r"cmd\.exe", r"/bin/bash", r"/proc/self", r"boot\.ini",
    r"win\.ini", r"system32",
]
SSRF_PATTERNS = [
    r"169\.254\.169\.254", #AWS metadata
    r"internal-",
    r"localhost",
    r"127\.0\.0\.1",
    r"0\.0\.0\.0",
    r"metadata\.google\.internal",
    r"@.*internal",
]
RCE_PATTERNS = [
    r";\s*ls\b", r"\|\s*cat\b", r"`id`", r"`whoami`",
    r"wget\s+http", r"curl\s+http", r"/bin/sh",
    r"\$\(.*\)", r"system\s*\(", r"exec\s*\(",
    r"base64\s+-d", r"nc\s+-",
]
SCANNER_UA = [
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster",
    "wfuzz", "hydra", "medusa", "nessus", "openvas", "acunetix",
    "burpsuite", "metasploit", "zgrab", "zmap",
]

SUSPICIOUS_SYSTEM_MSGS = [
    r"segment.?fault", r"buffer overflow", r"stack smash",
    r"privilege escalat", r"sudo.*FAILED", r"unauthorized",
    r"permission denied.*root", r"oom.?kill", r"kernel panic",
    r"rootkit", r"backdoor",
]

#HELPERS
def parse_ts(ts_str: str) -> datetime:
    """Parse ISO 8601 timestamp → datetime UTC."""
    if ts_str.endswith("Z"):
        ts_str = ts_str[:-1] + "+00:00"
    return datetime.fromisoformat(ts_str)


def matches_any(text: str, patterns: list[str]) -> str | None:
    """Retourne le premier pattern matché ou None."""
    text_lower = text.lower()
    for p in patterns:
        if re.search(p, text_lower):
            return p
    return None


def is_internal_ip(ip: str) -> bool:
    return ip.startswith(("10.", "192.168.", "172.16.", "172.17.",
                          "172.18.", "172.19.", "172.20.", "172.21.",
                          "172.22.", "172.23.", "172.24.", "172.25.",
                          "172.26.", "172.27.", "172.28.", "172.29.",
                          "172.30.", "172.31."))


def is_whitelisted(src: dict) -> bool:
    ip = src.get("source_ip", "")
    hostname = src.get("hostname", "")
    ua = src.get("user_agent", "")
    if ip in WHITELIST_IPS:
        return True
    if hostname in WHITELIST_HOSTNAMES:
        return True
    if any(ua.lower().startswith(p) for p in WHITELIST_UA_PREFIXES):
        return True
    return False


# SCORING

def compute_risk_score(tags: list[str], src: dict) -> int:
    score = 0
    tag_scores = {
        "high_risk_country": 10,
        "brute_force": 20,
        "credential_stuffing": 20,
        "sqli": 15,
        "xss": 10,
        "path_traversal": 15,
        "ssrf": 15,
        "rce": 25,
        "scanner_ua": 10,
        "impossible_travel": 25,
        "kill_chain": 30,
        "lateral_movement": 20,
        "data_exfiltration": 20,
        "suspicious_system": 15,
        "account_locked": 10,
        "port_scan": 15,
        "multi_port_internal": 10,
        "whitelisted": -10,
    }
    for tag in tags:
        score += tag_scores.get(tag, 0)
    return max(0, score)


#REGLES PAR LOG SOURCE

def apply_application_rules(src: dict) -> list[str]:
    tags = []
    uri = src.get("uri", "")
    ua = src.get("user_agent", "")
    combined = uri + " " + ua

    if matches_any(combined, SQLI_PATTERNS):
        tags.append("sqli")
    if matches_any(combined, XSS_PATTERNS):
        tags.append("xss")
    if matches_any(combined, PATH_TRAVERSAL_PATTERNS):
        tags.append("path_traversal")
    if matches_any(combined, SSRF_PATTERNS):
        tags.append("ssrf")
    if matches_any(combined, RCE_PATTERNS):
        tags.append("rce")
    if any(s in ua.lower() for s in SCANNER_UA):
        tags.append("scanner_ua")

    return tags


def apply_authentication_rules(src: dict) -> list[str]:
    tags = []
    country = src.get("geolocation_country", "")
    status = src.get("status", "")
    failure_reason = src.get("failure_reason", "")

    if country in HIGH_RISK_COUNTRIES:
        tags.append("high_risk_country")
    if status == "failure" and failure_reason == "account_locked":
        tags.append("account_locked")

    return tags


def apply_network_rules(src: dict) -> list[str]:
    tags = []
    action = src.get("action", "")
    bytes_sent = src.get("bytes_sent", 0) or 0
    src_ip = src.get("source_ip", "")
    dst_ip = src.get("destination_ip", "")

    if bytes_sent > EXFIL_BYTES_THRESHOLD and not is_internal_ip(src_ip):
        tags.append("data_exfiltration")

    # Trafic interne vers interne avec gros volume = mouvement latéral possible
    if is_internal_ip(src_ip) and is_internal_ip(dst_ip) and bytes_sent > 50_000:
        tags.append("lateral_movement")

    return tags


def apply_system_rules(src: dict) -> list[str]:
    tags = []
    message = src.get("message", "")
    severity = src.get("severity", "")
    process = src.get("process", "")

    if matches_any(message, SUSPICIOUS_SYSTEM_MSGS):
        tags.append("suspicious_system")

    # Syslog critique sur processus sensibles
    if severity in ("critical", "error") and process in ("auditd", "sshd", "sudo", "kernel"):
        tags.append("suspicious_system")

    return tags


# REGLES DE CORRELATION

def build_correlation_indexes(logs: list[dict]) -> dict:
    """
    Construit des index en mémoire pour les règles de corrélation :
    - auth_failures_by_ip : {ip: [timestamps]}
    - auth_usernames_by_ip : {ip: {usernames}}
    - auth_success_by_user : {username: [(timestamp, country)]}
    - network_ports_by_ip : {ip: {ports}}
    - alert_tags_by_ip : {ip: set(tags)} pour kill chain
    """
    auth_failures_by_ip: dict[str, list[datetime]] = defaultdict(list)
    auth_usernames_by_ip: dict[str, set] = defaultdict(set)
    auth_success_by_user: dict[str, list] = defaultdict(list)
    network_ports_by_ip: dict[str, set] = defaultdict(set)

    for entry in logs:
        src = entry["_source"]
        ip = src.get("source_ip", "")
        ts = parse_ts(src["timestamp"])
        log_source = src.get("log_source", "")

        if log_source == "authentication":
            username = src.get("username", "")
            country = src.get("geolocation_country", "")
            if src.get("status") == "failure":
                auth_failures_by_ip[ip].append(ts)
                auth_usernames_by_ip[ip].add(username)
            elif src.get("status") == "success":
                auth_success_by_user[username].append((ts, country))

        elif log_source == "network":
            port = src.get("destination_port")
            if port:
                network_ports_by_ip[ip].add(port)

    return {
        "auth_failures_by_ip": auth_failures_by_ip,
        "auth_usernames_by_ip": auth_usernames_by_ip,
        "auth_success_by_user": auth_success_by_user,
        "network_ports_by_ip": network_ports_by_ip,
    }


def check_brute_force(ip: str, ts: datetime, idx: dict) -> bool:
    failures = idx["auth_failures_by_ip"].get(ip, [])
    window_start = ts - timedelta(seconds=BRUTE_FORCE_WINDOW_SEC)
    recent = [t for t in failures if t >= window_start and t <= ts]
    return len(recent) >= BRUTE_FORCE_THRESHOLD


def check_credential_stuffing(ip: str, idx: dict) -> bool:
    usernames = idx["auth_usernames_by_ip"].get(ip, set())
    return len(usernames) >= CRED_STUFFING_USERNAMES


def check_impossible_travel(username: str, ts: datetime, current_country: str, idx: dict) -> bool:
    if not username or not current_country:
        return False
    successes = idx["auth_success_by_user"].get(username, [])
    window_start = ts - timedelta(hours=1)
    recent_countries = {c for t, c in successes if window_start <= t <= ts and c != current_country}
    return len(recent_countries) > 0


def check_port_scan(ip: str, idx: dict) -> bool:
    ports = idx["network_ports_by_ip"].get(ip, set())
    return len(ports) >= 10


#CLASSIFICATION PRINCIPALE

def classify_logs(logs: list[dict]) -> dict[str, Any]:
    print(f"- Chargement de {len(logs)} logs...")

    # Pré-calcul des index de corrélation
    print("- Construction des index de corrélation...")
    idx = build_correlation_indexes(logs)

    # Tracker kill chain : {ip: set(étapes)}
    kill_chain_by_ip: dict[str, set] = defaultdict(set)

    alerts = []
    stats = defaultdict(int)
    skipped_whitelist = 0

    print("- Application des règles...")

    for entry in logs:
        src = entry["_source"]
        log_source = src.get("log_source", "")
        ip = src.get("source_ip", "")
        ts = parse_ts(src["timestamp"])

        if is_whitelisted(src):
            skipped_whitelist += 1
            continue

        tags = []

        #règles par source
        if log_source == "application":
            tags += apply_application_rules(src)
        elif log_source == "authentication":
            tags += apply_authentication_rules(src)
            #corrélations auth
            if src.get("status") == "failure":
                if check_brute_force(ip, ts, idx):
                    tags.append("brute_force")
                    kill_chain_by_ip[ip].add("scan_or_brute")
                if check_credential_stuffing(ip, idx):
                    tags.append("credential_stuffing")
            elif src.get("status") == "success":
                kill_chain_by_ip[ip].add("auth_success")
                country = src.get("geolocation_country", "")
                username = src.get("username", "")
                if check_impossible_travel(username, ts, country, idx):
                    tags.append("impossible_travel")
        elif log_source == "network":
            tags += apply_network_rules(src)
            if check_port_scan(ip, idx):
                tags.append("port_scan")
                kill_chain_by_ip[ip].add("scan_or_brute")
        elif log_source == "system":
            tags += apply_system_rules(src)

        # Vérification kill chain : scan + brute + success = kill chain complète
        if "scan_or_brute" in kill_chain_by_ip.get(ip, set()) and \
           "auth_success" in kill_chain_by_ip.get(ip, set()):
            tags.append("kill_chain")

        # Mouvement latéral : IP interne avec tags offensifs
        if is_internal_ip(ip) and any(t in tags for t in ["sqli", "path_traversal", "rce", "ssrf"]):
            tags.append("lateral_movement")

        if not tags:
            continue

        # Déduplication des tags
        tags = list(set(tags))

        risk_score = compute_risk_score(tags, src)

        #niveau de sévérité
        if risk_score >= 70:
            severity = "critical"
        elif risk_score >= 40:
            severity = "high"
        elif risk_score >= 20:
            severity = "medium"
        else:
            severity = "low"

        alert = {
            "log_id": entry.get("_id"),
            "timestamp": src["timestamp"],
            "log_source": log_source,
            "source_ip": ip,
            "destination_ip": src.get("destination_ip"),
            "hostname": src.get("hostname"),
            "tags": sorted(tags),
            "risk_score": risk_score,
            "severity": severity,
            # Champs contextuels selon la source
            **({"uri": src.get("uri"), "http_method": src.get("http_method"),
                "status_code": src.get("status_code"), "user_agent": src.get("user_agent")}
               if log_source == "application" else {}),
            **({"username": src.get("username"), "auth_method": src.get("auth_method"),
                "status": src.get("status"), "failure_reason": src.get("failure_reason"),
                "geolocation_country": src.get("geolocation_country")}
               if log_source == "authentication" else {}),
            **({"protocol": src.get("protocol"), "destination_port": src.get("destination_port"),
                "bytes_sent": src.get("bytes_sent"), "action": src.get("action")}
               if log_source == "network" else {}),
            **({"process": src.get("process"), "severity_level": src.get("severity"),
                "message": src.get("message")}
               if log_source == "system" else {}),
        }

        alerts.append(alert)
        stats[severity] += 1
        for tag in tags:
            stats[f"tag_{tag}"] += 1

    #tri par risk_score décroissant
    alerts.sort(key=lambda x: -x["risk_score"])

    #résumé des IPs les plus dangereuses
    ip_summary: dict[str, dict] = defaultdict(lambda: {"count": 0, "max_score": 0, "tags": set()})
    for alert in alerts:
        ip = alert["source_ip"] or ""
        ip_summary[ip]["count"] += 1
        ip_summary[ip]["max_score"] = max(ip_summary[ip]["max_score"], alert["risk_score"])
        ip_summary[ip]["tags"].update(alert["tags"])

    top_ips = sorted(
        [{"ip": ip, **{k: list(v) if isinstance(v, set) else v for k, v in data.items()}}
         for ip, data in ip_summary.items()],
        key=lambda x: -x["max_score"]
    )[:20]

    result = {
        "meta": {
            "total_logs_processed": len(logs),
            "total_alerts": len(alerts),
            "skipped_whitelist": skipped_whitelist,
            "stats_by_severity": {
                "critical": stats["critical"],
                "high":     stats["high"],
                "medium":   stats["medium"],
                "low":      stats["low"],
            },
            "stats_by_tag": {k.replace("tag_", ""): v for k, v in stats.items() if k.startswith("tag_")},
            "top_attacker_ips": top_ips,
        },
        "alerts": alerts,
    }

    return result


def main():
    parser = argparse.ArgumentParser(description="Classify security logs with rule-based engine.")
    parser.add_argument("--input",  default="opensearch_last_logs.json", help="Fichier JSON d'entrée")
    parser.add_argument("--output", default="classified_alerts.json",    help="Fichier JSON de sortie")
    parser.add_argument("--min-score", type=int, default=0,              help="Score minimum pour inclure une alerte")
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as f:
        logs = json.load(f)

    result = classify_logs(logs)

    # Filtrer par score minimum si demandé
    if args.min_score > 0:
        before = len(result["alerts"])
        result["alerts"] = [a for a in result["alerts"] if a["risk_score"] >= args.min_score]
        print(f"[*] Filtrage score >= {args.min_score} : {before} → {len(result['alerts'])} alertes")

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    m = result["meta"]
    print(f"\n---- Résultats exportés dans {args.output}")
    print(f"   Logs traités  : {m['total_logs_processed']:,}")
    print(f"   Alertes       : {m['total_alerts']:,}")
    print(f"   Critical      : {m['stats_by_severity']['critical']:,}")
    print(f"   High          : {m['stats_by_severity']['high']:,}")
    print(f"   Medium        : {m['stats_by_severity']['medium']:,}")
    print(f"   Low           : {m['stats_by_severity']['low']:,}")
    print(f"\n   Top tags :")
    for tag, count in sorted(m["stats_by_tag"].items(), key=lambda x: -x[1])[:10]:
        print(f"     {tag}: {count}")
    print(f"\n   Top IPs suspectes :")
    for entry in m["top_attacker_ips"][:5]:
        print(f"     {entry['ip']} — score max: {entry['max_score']} — alertes: {entry['count']}")


if __name__ == "__main__":
    main()
