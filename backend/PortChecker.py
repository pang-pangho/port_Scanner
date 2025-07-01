import json
import requests
import time
from datetime import datetime

# asm.exe 서버 API 주소 (스캔 요청 및 결과 조회)
ASM_API_URL = "http://localhost:8080/api"

# Flask 서버 주소 (결과 저장용)
FLASK_SERVER_URL = "http://localhost:5001/report"

def request_nmap_scan(target, arguments="-F -sV"):
    print(f"[클라이언트] asm.exe 엔진에 스캔 요청: {target} (옵션: {arguments})")
    try:
        response = requests.post(f"{ASM_API_URL}/scan", json={"target": target, "arguments": arguments}, timeout=5)
        if response.status_code == 202:
            print("[클라이언트] 스캔 요청이 성공적으로 접수되었습니다.")
            return True
        else:
            print(f"[클라이언트] 엔진 응답 에러: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"[클라이언트] 통신 에러: asm.exe 엔진에 연결할 수 없습니다. ({e})")
        return False

def get_scan_results_from_asm(target, max_wait=30, interval=2):
    print(f"[클라이언트] asm.exe 엔진에서 '{target}'의 스캔 결과를 요청합니다.")
    for attempt in range(max_wait // interval):
        try:
            response = requests.get(f"{ASM_API_URL}/assets", timeout=5)
            response.raise_for_status()
            assets = response.json()

            for asset in assets:
                if asset.get("ip") == target or asset.get("hostname") == target:
                    results = []
                    for port_info in asset.get("ports", []):
                        results.append({
                            "ip": asset.get("ip"),
                            "port": port_info.get("port"),
                            "status": port_info.get("state"),
                            "service": port_info.get("service", "N/A"),
                            "version": port_info.get("version", "N/A"),
                            "timestamp": asset.get("last_scanned", datetime.now().isoformat())
                        })
                    print(f"[클라이언트] 스캔 결과 수신 완료 (시도 {attempt+1}회)")
                    return results

            print(f"[시도 {attempt+1}] 결과가 아직 준비되지 않았습니다. 다시 시도합니다...")
            time.sleep(interval)
        except Exception as e:
            print(f"[시도 {attempt+1}] 오류: {e}")
            time.sleep(interval)

    print("[클라이언트] 제한 시간 내에 스캔 결과를 가져오지 못했습니다.")
    return []

def save_results_to_json(results, filename="scan_results.json"):
    if not results:
        print("[클라이언트] 저장할 결과가 없습니다.")
        return
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        print(f"[클라이언트] 결과를 '{filename}' 파일로 저장했습니다.")
    except Exception as e:
        print(f"[클라이언트] 파일 저장 오류: {e}")

def send_results_to_flask(results, server_url=FLASK_SERVER_URL):
    if not results:
        print("[클라이언트] 전송할 결과가 없습니다.")
        return
    print(f"[클라이언트] Flask 서버({server_url})로 결과 전송 중...")
    try:
        res = requests.post(server_url, json=results)
        print(f"[클라이언트] Flask 서버 응답: HTTP {res.status_code} - {res.text}")
    except Exception as e:
        print(f"[클라이언트] Flask 서버 전송 실패: {e}")

if __name__ == "__main__":
    target_ip = input("스캔할 도메인/IP를 입력하세요: ").strip()
    if request_nmap_scan(target_ip):
        results = get_scan_results_from_asm(target_ip)
        save_results_to_json(results)
        send_results_to_flask(results)
