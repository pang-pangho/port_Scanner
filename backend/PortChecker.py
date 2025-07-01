import socket
import json
import requests
from datetime import datetime

def check_port(ip, port, timeout=1):
    """포트 열림 여부 확인"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return "open"
    except:
        return "closed"

def scan_ports(ip, ports):
    """여러 포트를 스캔하고 결과를 리스트로 반환"""
    results = []
    for port in ports:
        status = check_port(ip, port)
        print(f"[{ip}] Port {port} is {status}")
        results.append({
            "ip": ip,
            "port": port,
            "status": status,
            "timestamp": datetime.now().isoformat()
        })
    return results

def save_results_to_json(results, filename="results.json"):
    """결과를 JSON 파일로 저장"""
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)

def send_results_to_server(results, server_url):
    """Flask 서버로 POST 요청 전송"""
    try:
        res = requests.post(server_url, json=results)
        print(f"[서버 응답] {res.status_code} - {res.text}")
    except Exception as e:
        print(f"[오류] 서버 전송 실패: {e}")