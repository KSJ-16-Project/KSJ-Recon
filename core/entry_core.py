import sys
import os
import requests
from urllib.parse import urlparse

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
    #Nmap 모듈 호출
    scanner=ksj_nmap.ksj_nmap.NmapScanner()
    data = scanner.scan(url,1)
    print("데이터는", data)
    print("모듈 호출 성공")
else:
    print("명령어를 다시 입력하세요")





