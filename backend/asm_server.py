import os
import sqlite3
import subprocess
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
# Scapy 기반 직접 포트 스캔 함수
from scapy.all import IP, TCP, UDP, ICMP, sr1

app = Flask(__name__)
CORS(app)
DB_PATH = "asm.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            hostname TEXT,
            os TEXT,
            status TEXT,
            last_scanned TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER,
            port_number INTEGER NOT NULL,
            protocol TEXT,
            state TEXT,
            service_name TEXT,
            product TEXT,
            version TEXT,
            extra_info TEXT,
            FOREIGN KEY(asset_id) REFERENCES assets(id)
        )
    ''')
    conn.commit()
    conn.close()

def save_asset(ip, hostname, os, status, last_scanned, ports):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO assets (ip, hostname, os, status, last_scanned)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET hostname=excluded.hostname, os=excluded.os, status=excluded.status, last_scanned=excluded.last_scanned
    ''', (ip, hostname, os, status, last_scanned))
    conn.commit()
    c.execute('SELECT id FROM assets WHERE ip = ?', (ip,))
    asset_id = c.fetchone()[0]
    c.execute('DELETE FROM ports WHERE asset_id = ?', (asset_id,))
    for port in ports:
        c.execute('''
            INSERT INTO ports (asset_id, port_number, protocol, state, service_name, product, version, extra_info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (asset_id, port.get("port_number"), port.get("protocol"), port.get("state"),
              port.get("service_name"), port.get("product"), port.get("version"), port.get("extra_info")))
    conn.commit()
    conn.close()

def parse_nmap_xml(xml_str):
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_str)
    host = root.find("host")
    if host is None:
        return None
    ip = host.find("address").get("addr")
    status = host.find("status").get("state")
    hostname = ""
    os = ""
    ports = []
    if host.find("hostnames/hostname") is not None:
        hostname = host.find("hostnames/hostname").get("name")
    if host.find("os/osmatch") is not None:
        os = host.find("os/osmatch").get("name")
    for port in host.findall("ports/port"):
        port_number = int(port.get("portid"))
        protocol = port.get("protocol")
        state = port.find("state").get("state")
        service = port.find("service")
        service_name = service.get("name") if service is not None else ""
        product = service.get("product") if service is not None and "product" in service.attrib else ""
        version = service.get("version") if service is not None and "version" in service.attrib else ""
        extra_info = service.get("extrainfo") if service is not None and "extrainfo" in service.attrib else ""
        ports.append({
            "port_number": port_number,
            "protocol": protocol,
            "state": state,
            "service_name": service_name,
            "product": product,
            "version": version,
            "extra_info": extra_info
        })
    return {
        "ip": ip,
        "hostname": hostname,
        "os": os,
        "status": status,
        "ports": ports
    }

# --- 직접 포트 스캔 함수들 ---
def syn_scan(target_ip, port, timeout=1):
    pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        return "filtered"
    if resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x12:  # SYN-ACK
            return "open"
        elif resp.getlayer(TCP).flags == 0x14:  # RST-ACK
            return "closed"
    return "filtered"

def ack_scan(target_ip, port, timeout=1):
    pkt = IP(dst=target_ip)/TCP(dport=port, flags="A")
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        return "filtered"
    if resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x4:  # RST
            return "unfiltered"
    return "filtered"

def tcp_connect_scan(target_ip, port, timeout=1):
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((target_ip, port))
        s.close()
        return "open"
    except:
        return "closed"

def udp_scan(target_ip, port, timeout=2):
    pkt = IP(dst=target_ip)/UDP(dport=port)
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        return "open|filtered"
    if resp.haslayer(UDP):
        return "open"
    if resp.haslayer(ICMP):
        icmp_type = int(resp.getlayer(ICMP).type)
        icmp_code = int(resp.getlayer(ICMP).code)
        if icmp_type == 3 and icmp_code == 3:
            return "closed"
        elif icmp_type == 3 and icmp_code in [1,2,9,10,13]:
            return "filtered"
    return "unknown"

# --- API 엔드포인트 ---

@app.route("/api/assets")
def get_assets():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, ip, hostname, os, status, last_scanned FROM assets')
    assets = []
    for row in c.fetchall():
        asset_id, ip, hostname, os_, status, last_scanned = row
        c.execute('SELECT port_number, protocol, state, service_name, product, version, extra_info FROM ports WHERE asset_id=?', (asset_id,))
        ports = []
        for prow in c.fetchall():
            ports.append({
                "port": prow[0], "protocol": prow[1], "state": prow[2],
                "service": prow[3], "product": prow[4], "version": prow[5], "extra_info": prow[6]
            })
        assets.append({
            "id": asset_id, "ip": ip, "hostname": hostname, "os": os_, "status": status,
            "last_scanned": last_scanned, "ports": ports
        })
    conn.close()
    return jsonify(assets)

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target = data.get("target")
    ports = data.get("ports", "20-80")
    method = data.get("method", "nmap")
    port_list = []
    if "-" in ports:
        start, end = map(int, ports.split("-"))
        port_list = list(range(start, end+1))
    else:
        port_list = [int(ports)]
    if method == "nmap":
        # nmap 실행
        cmd = ["nmap", "-sV", "-O", "-oX", "-", target]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
        asset = parse_nmap_xml(proc.stdout)
        if asset:
            save_asset(asset["ip"], asset["hostname"], asset["os"], asset["status"], datetime.now().isoformat(), asset["ports"])
            return jsonify({"message": "nmap scan complete", "ip": asset["ip"]})
        else:
            return jsonify({"message": "scan failed"}), 500
    else:
        # 직접 스캔
        results = []
        for port in port_list:
            if method == "syn":
                status = syn_scan(target, port)
                proto = "tcp"
            elif method == "ack":
                status = ack_scan(target, port)
                proto = "tcp"
            elif method == "tcp":
                status = tcp_connect_scan(target, port)
                proto = "tcp"
            elif method == "udp":
                status = udp_scan(target, port)
                proto = "udp"
            else:
                status = "unknown"
                proto = "unknown"
            results.append({
                "ip": target, "port": port, "status": status, "protocol": proto,
                "service": "N/A", "version": "N/A", "timestamp": datetime.now().isoformat()
            })
        # 자산 저장 (간단화)
        save_asset(target, "", "", "up", datetime.now().isoformat(), [
            {"port_number": r["port"], "protocol": r["protocol"], "state": r["status"],
             "service_name": r["service"], "product": "", "version": r["version"], "extra_info": ""}
            for r in results
        ])
        return jsonify({"message": "scan complete", "ip": target, "results": results})

@app.route("/api/results")
def get_results():
    """최근 100건의 포트 스캔 결과를 테이블로 반환"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT a.ip, p.port_number, p.protocol, p.state, p.service_name, p.version, a.last_scanned
        FROM ports p
        JOIN assets a ON p.asset_id = a.id
        ORDER BY a.last_scanned DESC, p.port_number ASC
        LIMIT 100
    ''')
    rows = c.fetchall()
    conn.close()
    table = "<table border=1><tr><th>IP</th><th>Port</th><th>Proto</th><th>Status</th><th>Service</th><th>Version</th><th>Scanned</th></tr>"
    for row in rows:
        table += "<tr>" + "".join(f"<td>{v}</td>" for v in row) + "</tr>"
    table += "</table>"
    return table

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080)
