import os
import sqlite3
import subprocess
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from scapy.all import IP, TCP, UDP, ICMP, sr1
import vulners
import re
import socket
import requests
from fuzzywuzzy import process, fuzz

app = Flask(__name__)
CORS(app)

DB_PATH = "asm.db"

# Vulners에서 지원하는 대표 서비스명 리스트
VULNERS_SERVICES = [
    'OpenSSH', 'Apache httpd', 'nginx', 'MySQL', 'PostgreSQL', 'Microsoft IIS', 'ProFTPD', 'vsftpd', 'Exim', 'Dovecot',
    'Redis', 'MongoDB', 'Tomcat', 'Jetty', 'Node.js', 'PHP', 'Python', 'Ruby', 'Java', 'CUPS', 'Samba', 'SMB', 'FTP',
    'Telnet', 'SMTP', 'POP3', 'IMAP', 'DNS', 'Bind', 'ISC DHCP', 'Squid', 'Lighttpd', 'OpenVPN', 'OpenSSL', 'Dropbear',
    'Sendmail', 'Postfix', 'Qmail', 'Courier', 'Zimbra', 'Oracle', 'MariaDB', 'SQLite', 'Elasticsearch', 'RabbitMQ',
    'ActiveMQ', 'GlassFish', 'JBoss', 'WildFly', 'WebLogic', 'WebSphere'
]

vulners_api = vulners.VulnersApi(api_key="ND6XJH4JSYMEWFO8QMFJYRZPWQSHRNZ4HMDQ6KO0O5030FRUFAN25EQ110IYWX73")

def normalize_version(version):
    """버전 문자열에서 숫자+점+알파벳 조합만 추출 (예: 6.6.1p1)"""
    match = re.search(r"[0-9]+(\.[0-9]+)*[a-zA-Z0-9]*", version)
    return match.group(0) if match else version

def fuzzy_service_match(service_name):
    """퍼지 매칭으로 가장 유사한 서비스명 반환"""
    if not service_name:
        return service_name
    best, score = process.extractOne(service_name, VULNERS_SERVICES, scorer=fuzz.token_set_ratio)
    return best if score >= 80 else service_name  # 80점 이상일 때만 매칭 인정

def get_cve_info(service, version):
    """다중 방법을 활용한 강화된 취약점 검색"""
    print(f"DEBUG: 취약점 검색 - 서비스={service}, 버전={version}")
    cve_results = []
    
    # 방법 1: Vulners REST API 직접 호출 (가장 안정적)
    try:
        url = "https://vulners.com/api/v3/search/lucene/"
        headers = {'User-Agent': 'Vulners Python API'}
        params = {
            'apiKey': "ND6XJH4JSYMEWFO8QMFJYRZPWQSHRNZ4HMDQ6KO0O5030FRUFAN25EQ110IYWX73",
            'query': f"{service} {version}",
            'type': 'cve',
            'size': 50
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('result') == 'OK':
                search_results = data.get('data', {}).get('search', [])
                print(f"DEBUG: Vulners REST API에서 {len(search_results)}개 결과 발견")
                
                for item in search_results:
                    cve_results.append({
                        "cve": item.get("id", ""),
                        "cvss": item.get("cvss", {}).get("score", "정보 없음"),
                        "description": item.get("description", "")
                    })
        else:
            print(f"DEBUG: Vulners REST API 오류: {response.status_code}")
            
    except Exception as e:
        print(f"DEBUG: Vulners REST API 예외: {e}")
    
    # 방법 2: OSV API (오픈소스 취약점 데이터베이스)
    if not cve_results:
        try:
            osv_url = "https://api.osv.dev/v1/query"
            osv_data = {
                "package": {"name": service},
                "version": version
            }
            
            response = requests.post(osv_url, json=osv_data, timeout=10)
            if response.status_code == 200:
                osv_results = response.json().get('vulns', [])
                print(f"DEBUG: OSV API에서 {len(osv_results)}개 결과 발견")
                
                for vuln in osv_results:
                    cve_results.append({
                        "cve": vuln.get("id", ""),
                        "cvss": "정보 없음",
                        "description": vuln.get("summary", "")
                    })
                    
        except Exception as e:
            print(f"DEBUG: OSV API 오류: {e}")
    
    # 방법 3: 추가 검색 쿼리 시도 (Vulners)
    if not cve_results:
        try:
            # 다양한 검색 쿼리 시도
            search_queries = [
                f"{service.lower()} {version}",
                f"software:{service} version:{version}",
                f"{service} AND {version}",
                f"cpe:/a:*:{service.lower()}:{version}"
            ]
            
            for query in search_queries:
                print(f"DEBUG: 추가 검색 쿼리 시도: {query}")
                url = "https://vulners.com/api/v3/search/lucene/"
                headers = {'User-Agent': 'Vulners Python API'}
                params = {
                    'apiKey': "ND6XJH4JSYMEWFO8QMFJYRZPWQSHRNZ4HMDQ6KO0O5030FRUFAN25EQ110IYWX73",
                    'query': query,
                    'type': 'cve',
                    'size': 50
                }
                
                response = requests.get(url, headers=headers, params=params, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('result') == 'OK':
                        search_results = data.get('data', {}).get('search', [])
                        if search_results:
                            print(f"DEBUG: 추가 검색으로 {len(search_results)}개 결과 발견")
                            
                            for item in search_results:
                                cve_results.append({
                                    "cve": item.get("id", ""),
                                    "cvss": item.get("cvss", {}).get("score", "정보 없음"),
                                    "description": item.get("description", "")
                                })
                            break  # 결과가 있으면 다음 쿼리 시도하지 않음
                            
        except Exception as e:
            print(f"DEBUG: 추가 검색 오류: {e}")
    
    print(f"DEBUG: 최종 결과 {len(cve_results)}개 CVE")
    return cve_results[:10]  # 최대 10개까지만 반환

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
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
                cve_info TEXT,
                FOREIGN KEY(asset_id) REFERENCES assets(id)
            )
        ''')
        conn.commit()

def save_asset(ip, hostname, os, status, last_scanned, ports):
    with sqlite3.connect(DB_PATH) as conn:
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
                INSERT INTO ports (asset_id, port_number, protocol, state, service_name, product, version, extra_info, cve_info)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                asset_id,
                port.get("port_number"),
                port.get("protocol"),
                port.get("state"),
                port.get("service_name"),
                port.get("product"),
                port.get("version"),
                port.get("extra_info"),
                port.get("cve_info", "")
            ))
        conn.commit()

def parse_nmap_xml(xml_str):
    import xml.etree.ElementTree as ET
    if not xml_str.strip():
        return None
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None
    host = root.find("host")
    if host is None or host.find("address") is None:
        return None
    ip = host.find("address").get("addr")
    status = host.find("status").get("state") if host.find("status") is not None else ""
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
        state = port.find("state").get("state") if port.find("state") is not None else ""
        service = port.find("service")
        service_name = service.get("name") if service is not None else ""
        product = service.get("product") if service is not None and "product" in service.attrib else ""
        version = service.get("version") if service is not None and "version" in service.attrib else ""
        extra_info = service.get("extrainfo") if service is not None and "extrainfo" in service.attrib else ""
        
        # 퍼지 매칭 적용하여 CVE 정보 추가
        cve_info = ""
        if service_name and version:
            # 서비스명 퍼지 매칭
            matched_service = fuzzy_service_match(service_name)
            # 버전 정규화
            normalized_version = normalize_version(version)
            # CVE 정보 조회 (개선된 방법 사용)
            cve_list = get_cve_info(matched_service, normalized_version)
            if cve_list:
                cve_info = "; ".join([f"{c['cve']} (CVSS: {c['cvss']})" for c in cve_list])
        
        ports.append({
            "port_number": port_number,
            "protocol": protocol,
            "state": state,
            "service_name": service_name,
            "product": product,
            "version": version,
            "extra_info": extra_info,
            "cve_info": cve_info
        })
    return {
        "ip": ip,
        "hostname": hostname,
        "os": os,
        "status": status,
        "ports": ports
    }

def validate_ports(ports):
    """포트 범위 검증 및 파싱"""
    if isinstance(ports, int):
        return [ports]
    if "-" in ports:
        try:
            start, end = map(int, ports.split("-"))
            if start > end or start < 1 or end > 65535:
                return None
            return list(range(start, end+1))
        except Exception:
            return None
    try:
        port = int(ports)
        if 1 <= port <= 65535:
            return [port]
    except Exception:
        return None
    return None

def validate_target(target):
    """대상 IP/도메인 검증"""
    # IPv4 체크
    ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if re.match(ipv4_pattern, target):
        return True
    # 도메인 체크 (간단)
    domain_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
    if re.match(domain_pattern, target):
        return True
    # 실제로 DNS 조회 시도
    try:
        socket.gethostbyname(target)
        return True
    except Exception:
        return False

def syn_scan(target_ip, port, timeout=1):
    """SYN 스캔 구현"""
    pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        return "filtered"
    if resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x12:
            return "open"
        elif resp.getlayer(TCP).flags == 0x14:
            return "closed"
    return "filtered"

def ack_scan(target_ip, port, timeout=1):
    """ACK 스캔 구현"""
    pkt = IP(dst=target_ip)/TCP(dport=port, flags="A")
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        return "filtered"
    if resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x4:
            return "unfiltered"
    return "filtered"

def tcp_connect_scan(target_ip, port, timeout=1):
    """TCP Connect 스캔 구현"""
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
    """UDP 스캔 구현"""
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

@app.route("/api/assets", methods=["GET"])
def get_assets():
    """자산 목록 조회 (CVE 배열 형태로 변환) - CVSS 파싱 오류 수정"""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT id, ip, hostname, os, status, last_scanned FROM assets')
        assets = []
        for row in c.fetchall():
            asset_id, ip, hostname, os_, status, last_scanned = row
            c.execute('SELECT port_number, protocol, state, service_name, product, version, extra_info, cve_info FROM ports WHERE asset_id=?', (asset_id,))
            ports = []
            for prow in c.fetchall():
                # CVE 정보 파싱 (개선된 버전)
                cve_list = []
                cvss_score = 0
                risk_level = "low"
                
                if prow[7]:  # cve_info가 있는 경우
                    print(f"DEBUG: 원본 CVE 정보: {prow[7]}")
                    cve_entries = prow[7].split("; ")
                    for entry in cve_entries:
                        if "CVE-" in entry:
                            cve_id = entry.split(" (CVSS:")[0]
                            cve_list.append(cve_id)
                            # CVSS 점수 추출 (개선된 파싱)
                            if "CVSS:" in entry:
                                try:
                                    # 정규식을 사용한 더 정확한 파싱
                                    cvss_match = re.search(r'CVSS:\s*([0-9.]+)', entry)
                                    if cvss_match:
                                        score_str = cvss_match.group(1)
                                        if score_str and score_str != "정보 없음":
                                            score = float(score_str)
                                            cvss_score = max(cvss_score, score)
                                            print(f"DEBUG: CVE {cve_id} CVSS 점수: {score}")
                                except Exception as e:
                                    print(f"DEBUG: CVSS 파싱 오류: {e}, 원본: {entry}")
                
                # 위험도 계산 (디버깅 추가)
                if cvss_score >= 9.0:
                    risk_level = "critical"
                elif cvss_score >= 7.0:
                    risk_level = "high"
                elif cvss_score >= 4.0:
                    risk_level = "medium"
                elif cvss_score > 0:
                    risk_level = "low"
                else:
                    risk_level = "unknown"
                
                print(f"DEBUG: 포트 {prow[0]} - 최종 CVSS: {cvss_score}, 위험도: {risk_level}")
                
                ports.append({
                    "port": prow[0], "protocol": prow[1], "state": prow[2],
                    "service": prow[3], "product": prow[4], "version": prow[5], 
                    "extra_info": prow[6], "cve_info": prow[7],
                    "cve": cve_list,  # 배열 형태로 추가
                    "cvss_score": cvss_score,  # CVSS 점수 추가
                    "risk_level": risk_level   # 위험도 추가
                })
            assets.append({
                "id": asset_id, "ip": ip, "hostname": hostname, "os": os_, "status": status,
                "last_scanned": last_scanned, "ports": ports
            })
        return jsonify(assets)

@app.route("/api/vulnerabilities", methods=["GET"])
def get_vulnerabilities():
    """취약점 분석 전용 API - 취약점 분석 탭용"""
    vulnerabilities = []
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''
            SELECT a.ip, p.port_number, p.service_name, p.version, p.cve_info, a.last_scanned, p.product
            FROM ports p
            JOIN assets a ON p.asset_id = a.id
            WHERE p.cve_info IS NOT NULL AND p.cve_info != ""
            ORDER BY a.last_scanned DESC
        ''')
        
        for row in c.fetchall():
            ip, port, service, version, cve_info, last_scanned, product = row
            if cve_info:
                print(f"DEBUG: 취약점 분석 - {ip}:{port} CVE 정보 파싱")
                cve_entries = cve_info.split("; ")
                for entry in cve_entries:
                    if "CVE-" in entry:
                        cve_id = entry.split(" (CVSS:")[0]
                        cvss_score = 0
                        
                        if "CVSS:" in entry:
                            try:
                                cvss_match = re.search(r'CVSS:\s*([0-9.]+)', entry)
                                if cvss_match:
                                    score_str = cvss_match.group(1)
                                    if score_str and score_str != "정보 없음":
                                        cvss_score = float(score_str)
                            except Exception as e:
                                print(f"DEBUG: 취약점 분석 CVSS 파싱 오류: {e}")
                        
                        # 위험도 계산
                        if cvss_score >= 9.0:
                            severity = "critical"
                        elif cvss_score >= 7.0:
                            severity = "high"
                        elif cvss_score >= 4.0:
                            severity = "medium"
                        elif cvss_score > 0:
                            severity = "low"
                        else:
                            severity = "unknown"
                        
                        vulnerabilities.append({
                            "cve": cve_id,
                            "cvss_score": cvss_score,
                            "severity": severity,
                            "description": f"{service} {version} 취약점",
                            "service": service,
                            "product": product,
                            "version": version,
                            "port": port,
                            "ip": ip,
                            "published_date": last_scanned
                        })
    
    print(f"DEBUG: 총 {len(vulnerabilities)}개 취약점 반환")
    return jsonify(vulnerabilities)

@app.route("/api/assets/<int:asset_id>", methods=["DELETE", "OPTIONS"])
def delete_asset(asset_id):
    """자산 삭제"""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('DELETE FROM ports WHERE asset_id = ?', (asset_id,))
        c.execute('DELETE FROM assets WHERE id = ?', (asset_id,))
        conn.commit()
    return jsonify({"message": "deleted"}), 200

@app.route("/api/scan", methods=["POST"])
def scan():
    """포트 스캔 실행"""
    data = request.get_json()
    target = data.get("target")
    ports = data.get("ports", "20-80")
    method = data.get("method", "nmap")

    if not target or not validate_target(target):
        return jsonify({"message": "유효하지 않은 IP 또는 도메인입니다."}), 400
    port_list = validate_ports(ports)
    if not port_list:
        return jsonify({"message": "유효하지 않은 포트 범위입니다."}), 400

    if method == "nmap":
        cmd = ["nmap", "-sV", "-O", "-oX", "-", target]
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
        except Exception as e:
            return jsonify({"message": f"nmap 실행 오류: {str(e)}"}), 500

        if proc.returncode != 0:
            return jsonify({"message": f"nmap 오류: {proc.stderr.strip()}"}), 500

        if not proc.stdout.strip():
            return jsonify({"message": f"nmap 결과가 비어 있습니다. stderr: {proc.stderr.strip()}"}), 500

        asset = parse_nmap_xml(proc.stdout)
        if asset:
            save_asset(asset["ip"], asset["hostname"], asset["os"], asset["status"], datetime.now().isoformat(), asset["ports"])
            return jsonify({"message": "nmap scan complete", "ip": asset["ip"]})
        else:
            return jsonify({"message": "nmap 결과 파싱 실패"}), 500
    else:
        # 직접 스캔 방식 (SYN, ACK, TCP, UDP)
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
            # 직접 스캔은 서비스/버전 정보가 없으므로 cve_info는 빈 값
            results.append({
                "ip": target, "port": port, "status": status, "protocol": proto,
                "service": "정보 없음", "version": "정보 없음", "timestamp": datetime.now().isoformat(), "cve_info": ""
            })
        save_asset(target, "", "", "up", datetime.now().isoformat(), [
            {"port_number": r["port"], "protocol": r["protocol"], "state": r["status"],
             "service_name": r["service"], "product": "", "version": r["version"], "extra_info": "", "cve_info": r["cve_info"]}
            for r in results
        ])
        return jsonify({"message": "scan complete", "ip": target, "results": results})

@app.route("/api/results")
def get_results():
    """스캔 결과 테이블 형태로 반환"""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''
            SELECT a.ip, p.port_number, p.protocol, p.state, p.service_name, p.version, p.cve_info, a.last_scanned
            FROM ports p
            JOIN assets a ON p.asset_id = a.id
            ORDER BY a.last_scanned DESC, p.port_number ASC
            LIMIT 100
        ''')
        rows = c.fetchall()
    table = "<table border=1><tr><th>IP</th><th>Port</th><th>Proto</th><th>Status</th><th>Service</th><th>Version</th><th>CVE</th><th>Scanned</th></tr>"
    for row in rows:
        table += "<tr>" + "".join(f"<td>{v if v else '정보 없음'}</td>" for v in row) + "</tr>"
    table += "</table>"
    return table

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080)
