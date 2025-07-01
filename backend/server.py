from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
from PortChecker import scan_ports
import threading

app = Flask(__name__)
CORS(app)

# 임시 메모리 저장소 (실제 서비스에서는 DB 사용)
scan_results_db = {}
assets_db = []

@app.route("/scan", methods=["POST"])
def scan():
    """
    프론트엔드에서 스캔 요청이 오면 비동기로 포트 스캔을 실행하고,
    즉시 응답(202) 후 결과는 /scan-results/<ip>에서 조회
    """
    data = request.get_json()
    ip = data.get("ip")
    ports = data.get("ports", [22, 80, 443, 3306, 8080])
    scan_type = data.get("scan_type", "quick")

    # 스캔 비동기 실행
    def do_scan(ip, ports):
        results = scan_ports(ip, ports)
        # 서비스/버전/취약점 예시
        for r in results:
            if r["port"] == 22:
                r["service"] = "SSH"
                r["version"] = "OpenSSH 8.2"
                r["vulnerability"] = "medium"
            elif r["port"] == 80:
                r["service"] = "HTTP"
                r["version"] = "Apache 2.4.41"
                r["vulnerability"] = "low"
            elif r["port"] == 443:
                r["service"] = "HTTPS"
                r["version"] = "Apache 2.4.41"
                r["vulnerability"] = "low"
            elif r["port"] == 3306:
                r["service"] = "MySQL"
                r["version"] = "8.0.25"
                r["vulnerability"] = "high"
            elif r["port"] == 8080:
                r["service"] = "HTTP-Proxy"
                r["version"] = "Jetty 9.4"
                r["vulnerability"] = "medium"
            else:
                r["service"] = "unknown"
                r["version"] = ""
                r["vulnerability"] = "low"
        scan_results_db[ip] = results
        # 자산 정보도 갱신
        asset = {
            "id": len(assets_db) + 1,
            "ip": ip,
            "hostname": ip,
            "os": "Unknown",
            "status": "up",
            "last_scanned": datetime.now().isoformat(),
            "ports": [
                {
                    "port": r["port"],
                    "protocol": "tcp",
                    "state": r["status"],
                    "service": r.get("service", ""),
                    "product": r.get("service", ""),
                    "version": r.get("version", ""),
                }
                for r in results if r["status"] == "open"
            ]
        }
        # 중복 제거
        assets_db[:] = [a for a in assets_db if a["ip"] != ip]
        assets_db.append(asset)

    threading.Thread(target=do_scan, args=(ip, ports)).start()
    return jsonify({"message": "스캔 요청 접수"}), 202

@app.route("/scan-results/<ip>")
def get_scan_results(ip):
    """스캔 결과 반환"""
    results = scan_results_db.get(ip, [])
    return jsonify(results)

@app.route("/api/assets")
def get_assets():
    """자산 목록 반환"""
    return jsonify(assets_db)

@app.route("/attack/ssh", methods=["POST"])
def attack_ssh():
    """
    SSH 브루트포스 공격 실행 (예시: 결과만 반환)
    실제로는 ssh_bruteforce.py 연동 필요
    """
    data = request.get_json()
    # 실제로는 subprocess로 ssh_bruteforce.py 실행, 결과 파싱
    # 여기선 예시로 성공 응답
    return jsonify({
        "success": True,
        "credentials": {"username": "testuser", "password": "pass123"},
        "message": "SSH 로그인 성공"
    })

@app.route("/attack/web", methods=["POST"])
def attack_web():
    """
    웹 브루트포스 공격 실행 (예시: 결과만 반환)
    실제로는 web_bruteforce.py 연동 필요
    """
    data = request.get_json()
    # 실제로는 subprocess로 web_bruteforce.py 실행, 결과 파싱
    # 여기선 예시로 성공 응답
    return jsonify({
        "success": True,
        "credentials": {"username": "admin", "password": "password"},
        "message": "웹 로그인 성공"
    })

if __name__ == "__main__":
    app.run(debug=True, port=5001)
