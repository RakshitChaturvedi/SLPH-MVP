import os
import random
import json
from scapy.all import wrpcap, Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw

OUTPUT_DIR = "src/data"
OUTPUT_FILENAME = os.path.join(OUTPUT_DIR, "generated_traffic.pcap")

def create_http_packets():
    # Generate a list of scapy packets simulating different types of HTTP traffic.
    print("[*] Generating different types of HTTP packets...")
    packets = []

    # 1. Client Status Heartbeats (GET)
    for i in range (20):
        payload = (
            f"GET /api/v1/status?id=client_{i} HTTP/1.1\r\n"
            f"Host: api.service.local\r\n"
            f"User-Agent: SLPH-Monitor/1.0\r\n"
            f"\r\n"
        )
        packets.append(IP(dst="10.0.0.1")/TCP() / Raw(load=payload.encode('utf-8')))

    # 2. Client Data Uploads (POST w JSON)
    for i in range(15):
        json_data = {
            "sensor_id": f"sensor_{random.randint(1,5)}",
            "timestampt": 1672531200 + i,
            "value": round(random.uniform(20.0, 30.0), 2)
        }
        json_str = json.dumps(json_data)
        payload = (
            f"POST /api/v1/data HTTP/1.1\r\n"
            f"Host: api.service.local\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(json_str)}\r\n"
            f"\r\n"
            f"{json_str}"
        )
        packets.append(IP(dst="10.0.0.1")/TCP() / Raw(load=payload.encode('utf-8')))

    # 3. Server OK Response (200 OK)
    for i in range(25):
        json_response = {"status": "ok", "ack_id": 1000+i}
        json_str = json.dumps(json_response)
        payload = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(json_str)}\r\n"
            f"\r\n"
            f"{json_str}"
        )
        packets.append(IP(src="10.0.0.1")/TCP() / Raw(load=payload.encode('utf-8')))

    # 4. Server not found response (404 Not Found) 
    for _ in range(10):
        payload = (
            f"HTTP/1.1 404 Not Found\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
        )
        packets.append(IP(src="10.0.0.1")/TCP() / Raw(load=payload.encode('utf-8')))

    # 5. DNS Queries (UDP)
    dns_queries = ["api.service.local", "assets.cdn.local", "auth.service.local"]
    for i in range(12):
        query = random.choice(dns_queries)
        packets.append(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=query)))

    # 6. DNS Responses (UDP)
    for i in range(12):
        query = random.choice(dns_queries)
        ip_addr = f"10.0.0.{random.randint(10, 20)}"
        packets.append(IP(src="8.8.8.8", dst="10.0.0.1")/UDP(sport=53)/DNS(id=random.randint(1,65535), qr=1, an=DNSRR(rrname=query, ttl=60, rdata=ip_addr)))

    # 7. Client Authentication (POST with form data)
    for i in range(8):
        auth_data = f"username=user{i}&password=password{i}"
        payload = (
            f"POST /auth/login HTTP/1.1\r\n"
            f"Host: auth.service.local\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(auth_data)}\r\n"
            f"\r\n"
            f"{auth_data}"
        )
        packets.append(IP(dst="10.0.0.2")/TCP(dport=443) / Raw(load=payload.encode('utf-8')))

    # 8. Server Auth Failure (401 Unauthorized)
    for _ in range(5):
        payload = (
            f"HTTP/1.1 401 Unauthorized\r\n"
            f"WWW-Authenticate: Basic realm=\"Secure Area\"\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
        )
        packets.append(IP(src="10.0.0.2")/TCP(sport=443) / Raw(load=payload.encode('utf-8')))

    # 9. Image Download (GET for binary data)
    for i in range(7):
        payload = (
            f"GET /assets/image_{i}.jpg HTTP/1.1\r\n"
            f"Host: assets.cdn.local\r\n"
            f"Accept: image/jpeg\r\n"
            f"\r\n"
        )
        packets.append(IP(dst="10.0.0.3")/TCP() / Raw(load=payload.encode('utf-8')))
    
    # 10. Server Internal Error (500)
    for _ in range(4):
        error_body = "<h1>Internal Server Error</h1>"
        payload = (
            f"HTTP/1.1 500 Internal Server Error\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: {len(error_body)}\r\n"
            f"\r\n"
            f"{error_body}"
        )
        packets.append(IP(src="10.0.0.1")/TCP() / Raw(load=payload.encode('utf-8')))
    
    print(f"[+] Generated a total of {len(packets)} packets.")
    return packets

def main():
    if not os.path.exists(OUTPUT_DIR):
        print(f"[*] Creating data directory: {OUTPUT_DIR}")
        os.makedirs(OUTPUT_DIR)

    generated_packets = create_http_packets()

    print(f"[*] Writing packets to '{OUTPUT_FILENAME}'...")
    wrpcap(OUTPUT_FILENAME, generated_packets)
    print(f"[+] Successfully created PCAP file.")

if __name__ == "__main__":
    main()