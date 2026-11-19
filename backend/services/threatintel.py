"""LOCAL threat-intel indicators (sample data, fictional documentation-range IPs). No live lookups are ever made."""
LOCAL_INTEL = {
 "203.0.113.45": {"tag": "Known DDoS source (local sample list)", "confidence": "high"},
 "198.51.100.23": {"tag": "Scanner seen in earlier campaign (local sample list)", "confidence": "medium"},
 "203.0.113.99": {"tag": "Credential-stuffing node (local sample list)", "confidence": "medium"},
 "192.0.2.77": {"tag": "Botnet C2 relay (local sample list)", "confidence": "high"},
}
def check(ip):
    h = LOCAL_INTEL.get(ip)
    return {"ip": ip, "listed": bool(h), "source": "local indicator list (offline)", **(h or {})}
