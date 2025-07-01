# test_checker.py

from PortChecker import scan_ports, save_results_to_json

ip = "demo.testfire.net"
port_range = range(20, 50)  # 원하는 범위 조정 가능

# 스캔 실행
scan_result = scan_ports(ip, port_range)

# 결과 저장
save_results_to_json(scan_result)