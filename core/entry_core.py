import sys
import os
import requests
from urllib.parse import urlparse
from middle_core import Middle_core
import json
# 1. 현재 파일(entry_core.py)의 부모의 부모인 'KSJ-RECON' 폴더 경로를 찾습니다.
root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 2. 파이썬이 파일을 찾을 때 이 루트 경로도 뒤지도록 추가합니다.
if root_path not in sys.path:
    sys.path.append(root_path)

import ksj_nmap.ksj_nmap 

#Nmap 모듈 호출
def call_nmap_module():
    return
#Crawler 모듈 호출
def call_crawler_module():
    return

# 명령어 검사 로직 
def check_isOrder(command_input):
    global url
    #1. 간단한 명령어 패턴 검사
    if not command_input.startswith("recon"):
        print("Error : 올바른 명령어가 아닙니다.")
        return False
    
    # 2. URL 추출 및 파싱
    # 입력 예시 : "recon start [L1] URL"
    # URL 형식이 맞는지 검사 -> http , https인지 확인
    try:
        parts=command_input.split()
        if len(parts)<4:
            return False
        # 명령어 단어 하나하나마다 검사
        target_url =parts[3]
        parsed =urlparse(target_url)

        # 프로토콜 확인
        if parsed.scheme not in ['http','https']:
            print(f"올바른 URL을 입력해주세요.")
            return False
    except Exception as e:
        print(f"Parsing Error: {e}")
        return False
    
    # 3. URL이 실제로 접근되는지?
    try:
        #timeout을 설정하여 무한 대기를 방지한다.
        response = requests.get(target_url , timeout=5)

        if response.status_code==200:
            print(f"Success: {target_url}에 접근 가능합니다. Nmap 모듈을 호출합니다.")
            url=target_url
            return True
        else:
            print(f"Warning: 페이지 응답 코드 {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Connection Error : 실제 페이지에 접근할 수 없습니다.\n{e}")
        return False

url=""
# 명령어 입력
# recon start L1 [URL] 로 입력해서 데이터 가져오면 됩니다.
print("명령어를 입력하세요:")
order = sys.stdin.readline().strip()
print("초기 order", order)
if check_isOrder(order):
    # Nmap 모듈 호출
    scanner=ksj_nmap.ksj_nmap.NmapScanner()
    data = scanner.scan(url,1)
    print("데이터는", data)
    print("Nmap 모듈 호출 성공")

    # middle_core 모듈 호출
    print("Middle core 테스트 시작")
    mid_core=Middle_core()
    mid_core.get_nmap_data({
        "target": "https://hotspotfan.online",
        "status": "up",
        "ip_address": "192.168.0.100",
        "open_ports": [
            {
                "port": 80,
                "service": "http",
                "version": "Apache httpd 2.4.41"
            },
            {
                "port": 443,
                "service": "https",
                "version": "OpenSSL 1.1.1f"
            }
        ],
        "os_guess": "Ubuntu Linux"
    })

    mid_core.get_crawler_data({
        "base_url": "https://hotspotfan.online",
        "total_pages": 3,
        "discovered_links": [
            "https://hotspotfan.online/",
            "https://hotspotfan.online/login.php",
            "https://hotspotfan.online/board/view.php?id=1"
        ],
        "forms": [
            {
                "action": "/login.php",
                "method": "POST",
                "inputs": ["username", "password"]
            },
            {
                "action": "/board/view.php",
                "method": "GET",
                "inputs": ["id"]
            }
        ]
    })

    mid_core.get_fuzzer_data({
        "scan_summary": {
            "vulnerabilities_found": 2,
            "severity": "High"
        },
        "details": [
            {
                "type": "Reflected XSS",
                "url": "https://hotspotfan.online/board/view.php",
                "parameter": "id",
                "payload": "<script>alert(1)</script>",
                "evidence": "Alert box triggered in response body"
            },
            {
                "type": "SQL Injection",
                "url": "https://hotspotfan.online/login.php",
                "parameter": "username",
                "payload": "' OR 1=1 --",
                "evidence": "Authentication bypass successful"
            }
        ]
    })
    results=mid_core.get_all_results()
    print(json.dumps(results, indent=4, ensure_ascii=False))
    print("Middle_core 테스트 끝")
else:
    print("명령어를 다시 입력하세요")


# 순서
# Nmap 모듈 호출 후 데이터 받기
# Crawler 모듈 호출 후 데이터 받아서 Fuzzer 모듈에 전달
# Fuzzer 모듈 호출 후 데이터 받기
# Nmap , Crawler , Fuzzer 데이터 정제 후  한개로 합쳐 Middle Core에 한꺼번에 전달
# Middle core에서 데이터 받기
# 받은 데이터로 LLm 모듈에 전달 후 보고서 받기

# 구현 체크리스트
# 1. 세부적인 파싱 요소 , Level 에서 숫자 파싱 후 전달
# 2. 명령어 단어 싹 다 검사
# 3. 



