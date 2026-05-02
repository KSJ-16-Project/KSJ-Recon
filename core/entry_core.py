import sys
import os
import requests
from urllib.parse import urlparse
from middle_core import Middle_core
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn ,BarColumn
import pyfiglet

# 1. 현재 파일(entry_core.py)의 부모의 부모인 'KSJ-RECON' 폴더 경로를 찾습니다.
root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 2. 파이썬이 파일을 찾을 때 이 루트 경로도 뒤지도록 추가합니다.
if root_path not in sys.path:
    sys.path.append(root_path)

import ksj_nmap.ksj_nmap 
from ffuf_module.fuzzer_module import FuzzOrchestrator

# Rich 콘솔 초기화
console = Console()

def print_banner():
    ascii_banner = pyfiglet.figlet_format("KSJ-RECON", font="slant")
    console.print(Panel(f"[bold cyan]{ascii_banner}[/bold cyan]", subtitle="[yellow]v1.0.0 - Modular Recon Platform[/yellow]"))
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


# --- 메인 실행부 ---
print_banner()

# 명령어 입력
# recon start L1 [URL] 로 입력해서 데이터 가져오면 됩니다.
console.print("\n[bold yellow]명령어를 입력하세요 (예: recon start L1 http://example.com):[/bold yellow]")
order = sys.stdin.readline().strip()

start = time.time()
if check_isOrder(order):
    # Nmap 모듈 호출
    scanner=ksj_nmap.ksj_nmap.NmapScanner()
    fuzzer=FuzzOrchestrator()

    # 1. ThreadPoolExecutor 생성
    with Progress(
    SpinnerColumn(),
    TextColumn("[progress.description]{task.description}"),
    BarColumn(),
    transient=False, # 완료 후 진행바 남기기
    ) as progress:
        
        # 개별 작업 바 생성
        task1 = progress.add_task("[cyan]Nmap 모듈 동작중...", total=1)
        task2 = progress.add_task("[magenta]Fuzzer 모듈 동작중...", total=1)
        
        nmap_data, fuzzer_data = {}, []

        try:
            with ThreadPoolExecutor(max_workers=3) as executor:
            # 여기에도 상태 표시 하고싶은데?
                future_nmap=executor.submit(scanner.scan,url,level)
                future_fuzzer=executor.submit(
                    fuzzer.run,
                    base_url    = "http://gym.contentshub.kr:58252/",  # 필수
                    spider_urls = ["http://gym.contentshub.kr:58252/kisec", "http://gym.contentshub.kr:58252/kisec/main"],  # 필수 (없으면 [])
                    difficulty  = 1,  # 필수: 1(이지) or 2(하드)
                )
                # 2. 핵심: 완료되는 순서대로 처리 (as_completed 사용)
                from concurrent.futures import as_completed
                futures = {future_nmap: "nmap", future_fuzzer: "fuzzer"}

                for future in as_completed(futures):
                    target = futures[future]
                    result = future.result()
                    
                    if target == "nmap":
                        nmap_data = result
                        progress.update(task1, advance=1, description="[bold green]✔ Nmap 스캔 완료")
                    elif target == "fuzzer":
                        fuzzer_data = result
                        progress.update(task2, advance=1, description="[bold green]✔ Fuzzer 완료")
        
        except Exception as e:
            console.print(f"[bold red] KSJ-RECON 실행 중 오류 발생: {e}")
   
        # --- 5. Middle Core 연동 (Progress 밖에서 실행) ---
    console.print("\n[bold blue]>>> Middle core 분석 및 데이터 통합 시작[/bold blue]")
    mid_core = Middle_core()

    mid_core.get_nmap_data(nmap_data)
    mid_core.get_fuzzer_data(fuzzer_data)

    results = mid_core.get_all_results()

    # 결과물 출력 최적화 (Rich 전용 JSON 출력)
    console.print(Panel("[bold white]최종 통합 결과 데이터 (JSON)[/bold white]", border_style="yellow"))
    console.print_json(data=results)
    console.print("[bold green]Middle_core 테스트 끝[/bold green]")
    end = time.time()
    print(f"소요 시간: {end - start:.2f}초")
else:
    console.print("[bold red]✘ Error: 명령어를 다시 입력하세요.[/bold red]")



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



