import sys
import os
import requests
from urllib.parse import urlparse
from middle_core import Middle_core
import json
import time
from concurrent.futures import ThreadPoolExecutor

# 1. 현재 파일(entry_core.py)의 부모의 부모인 'KSJ-RECON' 폴더 경로를 찾습니다.
root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 2. 파이썬이 파일을 찾을 때 이 루트 경로도 뒤지도록 추가합니다.
if root_path not in sys.path:
    sys.path.append(root_path)

import ksj_nmap.ksj_nmap 
from ffuf_module.fuzzer_module import FuzzOrchestrator

# 명령어 검사 로직 
def check_isOrder(command_input):
    global url
    global level

    #1. 간단한 명령어 패턴 검사
    if not command_input.startswith("recon"):
        print("Error : 올바른 명령어가 아닙니다.")
        return False
    
    # 2. URL 추출 및 파싱
    # 입력 예시 : "recon start [L1] URL" -> 최소 형식 
    try:
        parts=command_input.split()
        if len(parts)<4:
            return False
        
        # Level이 잘 입력됐는지 검사
        try:
            level = int(parts[2][1:].strip())
        except ValueError:
            return False
        
        target_url =parts[3]
        parsed =urlparse(target_url)

        # URL 형식이 맞는지 검사 -> http , https인지 확인
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

level=0
url=""

# level 1 -> nmap low , fuzzer low
# level 2 -> nmap hard , fuzzer low
# level 3 -> nmap low , fuzzer hard
# level 4 -> nmap hard , fuzzer hard
level_mode=[[1,1],[2,1],[1,2],[2,2]]

# 명령어 입력
# recon start L1 [URL] 로 입력해서 데이터 가져오면 됩니다.
print("명령어를 입력하세요:")
order = sys.stdin.readline().strip()
print("초기 order", order)
start = time.time()
if check_isOrder(order):
    # Nmap 모듈 호출
    scanner=ksj_nmap.ksj_nmap.NmapScanner()
    fuzzer=FuzzOrchestrator()

    # 1. ThreadPoolExecutor 생성
    with ThreadPoolExecutor(max_workers=3) as executor:
        future_nmap=executor.submit(scanner.scan,url,level)

        future_fuzzer=executor.submit(
            fuzzer.run,
            base_url    = "http://gym.contentshub.kr:58252/",  # 필수
            spider_urls = ["http://gym.contentshub.kr:58252/kisec", "http://gym.contentshub.kr:58252/kisec/main"],  # 필수 (없으면 [])
            difficulty  = 1,  # 필수: 1(이지) or 2(하드)
        )
    print("병렬 스레드 진행중 ")
    # nmap_data = scanner.scan(url,level)
    try:
        nmap_data=future_nmap.result()
        #print("Nmap 데이터는", nmap_data)

        fuzzer_data=future_fuzzer.result()
        #print("Fuzzer 데이터는", fuzzer_data)
    except Exception as e:
        print(" 병렬 스레드 실행 중 오류 발생 , {e}")
#     fuzzer_data= FuzzOrchestrator().run(
#     base_url    = "http://gym.contentshub.kr:58252/",  # 필수
#     spider_urls = ["http://gym.contentshub.kr:58252/kisec", "http://gym.contentshub.kr:58252/kisec/main"],  # 필수 (없으면 [])
#     difficulty  = 1,  # 필수: 1(이지) or 2(하드)
# )
    # middle_core 모듈 호출
    print("Middle core 테스트 시작")
    mid_core=Middle_core()

    mid_core.get_nmap_data(nmap_data)
    # mid_core.get_crawler_data()
    mid_core.get_fuzzer_data(fuzzer_data)

    results=mid_core.get_all_results()
    print(json.dumps(results, indent=4, ensure_ascii=False))
    print("Middle_core 테스트 끝")
else:
    print("명령어를 다시 입력하세요")
end = time.time()
print(f"소요 시간: {end - start:.2f}초")


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



