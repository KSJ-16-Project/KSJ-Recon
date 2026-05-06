import sys
import asyncio
import os
import requests
from urllib.parse import urlparse
from middle_core import Middle_core
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn 
import pyfiglet
import questionary
from questionary import Choice
from questionary import Style
import dataclasses

# 1. 현재 파일(entry_core.py)의 부모의 부모인 'KSJ-RECON' 폴더 경로를 찾습니다.
root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 2. 파이썬이 파일을 찾을 때 이 루트 경로도 뒤지도록 추가합니다.
if root_path not in sys.path:
    sys.path.append(root_path)

import ksj_nmap.ksj_nmap 
from ffuf_module.fuzzer_module import FuzzOrchestrator
# from ksj_llm.ksj_llm import LLMReporter
from crawler.engine import crawl_target , CrawlerConfig
from crawler.auth.models import AuthConfig
from ksj_llm.preprocessor import LLMPreprocessor
from sql_injection.scanner import  run_scan,ScanInput
from XSS.xss_module.xss_scanner import run_xss_scan
from attacker_module_3.file_download.module import FileDownloadModule
from attacker_module_3.ssrf.module import SSRFModule
# Rich 콘솔 초기화
console = Console()

# async def save_to_txt(target_full_path, content):
#     """
#     target_full_path: 저장할 파일의 전체 경로 (예: 'C:/output/test.txt')
#     content: 저장할 내용 (문자열)
#     """
#     try:
#         # 1. 파일이 저장될 폴더 경로 추출
#         directory = os.path.dirname(target_full_path)

#         # 2. 폴더가 없으면 생성 (exist_ok=True는 이미 폴더가 있어도 에러를 내지 않음)
#         if directory and not os.path.exists(directory):
#             os.makedirs(directory, exist_ok=True)
#             print(f"새로운 디렉토리를 생성했습니다: {directory}")

#         # 3. 파일 쓰기 (utf-8 인코딩으로 한글 깨짐 방지)
#         with open(target_full_path, 'w', encoding='utf-8') as f:
#             f.write(content)
        
#         print(f"성공적으로 파일을 저장했습니다: {target_full_path}")
        
#     except Exception as e:
#         print(f"파일 저장 중 오류 발생: {e}")

# Url 검사 로직
def check_Url(recon_url):
    
    try:
        # URL 뽑아내기
        parsed =urlparse(recon_url)

        # URL 형식이 맞는지 검사 -> http , https인지 확인
        if parsed.scheme not in ['http','https']:
            console.print("[bold red]✘ 올바른 URL를 입력하세요.[/bold red]")
            return False
    except Exception as e:
        print(f"Parsing Error: {e}")
        return False
    
    # 3. URL이 실제로 접근되는지?
    try:
        #timeout을 설정하여 무한 대기를 방지한다.
        response = requests.get(recon_url , timeout=5)

        if response.status_code==200:
            return True
        else:
            console.print(f"[bold red]✘ URL에 접근할 수 없습니다. {response.status_code}[/bold red]")
            return False
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]✘ URL에 접근할 수 없습니다.[/bold red]")
        return False

# KSJ-Recon 배너
def print_banner():
    ascii_banner = pyfiglet.figlet_format("KSJ-RECON", font="slant")
    console.print(Panel(f"[bold cyan]{ascii_banner}[/bold cyan]", subtitle="[yellow]v1.0.0 - Modular Recon Platform[/yellow]"))


# level 1 -> nmap low , fuzzer low
# level 2 -> nmap hard , fuzzer low
# level 3 -> nmap low , fuzzer hard
# level 4 -> nmap hard , fuzzer hard
level_mode=[[1,1],[2,1],[1,2],[2,2]]


# --- 메인 실행부 ---
print()
print_banner()
print()

# Level 선택지 스타일 정의
custom_style = Style([
    ('qmark', 'fg:#673ab7 bold'),       # 질문 기호 색상
    ('question', 'bold'),               # 질문 텍스트
    ('pointer', 'fg:#ff5252 bold'),      # 화살표 색상 (강렬한 레드)
    ('highlighted', 'fg:#ff5252 bold'),  # 선택된 항목 색상
    ('selected', 'fg:#ccff00'),          # 최종 선택 후 색상
    ('pointer', 'fg:#ff5252 bold'),
])

recon_mode=""
mode_choice = questionary.select(
    "Mode를 선택하세요",
    choices=[
        Choice(title="Mode A : Recon", value=1),
        Choice(title="Mode B : Recon + Attack", value=2)
    ],
    style=custom_style,
    pointer='▶',
    instruction=" "
).ask()

sys.stdout.write("\033[A\033[K")

mode_explain=""
if mode_choice == 1:
    mode_explain = "Mode A : Recon"
    recon_mode="mode_a"
else:
    mode_explain = "Mode B : Recon + Attack"
    recon_mode="mode_b"

console.print(f"[bold green]✔[/] 선택한 Mode : [orange1]{mode_explain}[/]")

print()
# 레벨 선택
level_choice = questionary.select(
    "진단 레벨을 선택하세요",
    choices=[
        Choice(title="Level 1 (Nmap: Low / Fuzzer: Low)", value=1),
        Choice(title="Level 2 (Nmap: Hard / Fuzzer: Low)", value=2),
        Choice(title="Level 3 (Nmap: Low / Fuzzer: Hard)", value=3),
        Choice(title="Level 4 (Nmap: Hard / Fuzzer: Hard)", value=4),
    ],
    style=custom_style,
    pointer='▶',
    instruction=" "
).ask()


sys.stdout.write("\033[A\033[K")

level_explain=""
if level_choice == 1:
    level_explain = "Level 1 (Nmap: Low / Fuzzer: Low)"
elif level_choice == 2:
    level_explain = "Level 2 (Nmap: Hard / Fuzzer: Low)"
elif level_choice == 3:
    level_explain = "Level 3 (Nmap: Low / Fuzzer: Hard)"
else:
    level_explain = "Level 4 (Nmap: Hard / Fuzzer: Hard)"

console.print(f"[bold green]✔[/] 선택한 진단 레벨: [orange1]{level_explain}[/]")

# 선택한 레벨에 맞게 nmap , fuzzer 레벨 설정
nmap_level=level_mode[level_choice-1][0]
fuzzer_level=level_mode[level_choice-1][1]

print()
# 로그인 페이지 존재 여부 
login_choice = questionary.select(
    "로그인이 필요한 도메인입니까??",
    choices=[
        Choice(title="로그인이 필요합니다.", value=1),
        Choice(title="로그인이 필요하지 않습니다.", value=2)
    ],
    style=custom_style,
    pointer='▶',
    instruction=" "
).ask()

sys.stdout.write("\033[A\033[K")

login_explain=""
user_id=""
user_password=""
if login_choice == 1:
    login_explain = "로그인 정보 입력 완료"
    # URL 입력
    console.print("\n[bold yellow]아이디를 입력하세요[/bold yellow]")
    user_id = sys.stdin.readline().strip()
    console.print("\n[bold yellow]패스워드를 입력하세요[/bold yellow]")
    user_password = sys.stdin.readline().strip()
    print()
else:
    login_explain = "로그인이 필요하지 않은 도메인입니다."

console.print(f"[bold green]✔[/] 로그인 필요 여부: [orange1]{login_explain}[/]")

# URL 입력
console.print("\n[bold yellow]URL를 입력하세요[/bold yellow]")
recon_url = sys.stdin.readline().strip()
print()



#검사 시간 측정
start = time.time()

if check_Url(recon_url):

    # mid_core = Middle_core(recon_url)

    with Progress(
    SpinnerColumn(),
    TextColumn("[progress.description]{task.description}",justify="left"),
    transient=False, 
    ) as progress:
        
        
    #     if login_choice==1:
    #         # 로그인이 필요한 도메인이면
    #         config = CrawlerConfig(
    #             target_url=recon_url, # check_isOrder에서 검증된 url
    #             auth = AuthConfig(
    #                 username = user_id,
    #                 password = user_password,
    #             )
    #         )
    #     else:
    #         # Crawler 설정 (config 생성)
    #         config = CrawlerConfig(
    #             target_url=recon_url # check_isOrder에서 검증된 url
    #         )


    #     # Crawler 전용 프로그레스 바
    #     crawl_task = progress.add_task("[red]Crawler 모듈 동작중...", total=1)
        
    #     # 비동기 함수인 crawl_target 실행 및 결과 수령
    #     crawl_data = asyncio.run(crawl_target(config))
        
    #     #json으로 변환
    #     final_crawl_data=dataclasses.asdict(crawl_data)
       
    #     # 크롤러 데이터에서 Fuzzer 모듈을 위한 URL 리스트 뽑기 ( 미들 코어에서 )
    #     spider_urls=asyncio.run(mid_core.make_url_list(final_crawl_data))
    #     # print("스파이더",spider_urls)
    #     print("미들 코어에서 나온",spider_urls)
    #     mid_core.set_crawler_data(final_crawl_data)

       
        
    #     progress.update(crawl_task, advance=1, description="[bold red]✔ Crawler 분석 완료")
        
        
    #     # 개별 작업 바 생성
    #     task1 = progress.add_task("[cyan]Nmap 모듈 동작중...", total=1)
    #     task2 = progress.add_task("[magenta]Fuzzer 모듈 동작중...", total=1)
        
    #      # Nmap 모듈 생성
    #     scanner=ksj_nmap.ksj_nmap.NmapScanner()

    #     # Fuzzer 모듈 생성
    #     fuzzer=FuzzOrchestrator()
        
    #     nmap_data, fuzzer_data = {}, []

    #     try:
    #         with ThreadPoolExecutor(max_workers=2) as executor:

    #             # Nmap 모듈 작동
    #             future_nmap=executor.submit(scanner.scan,recon_url,nmap_level)
                
    #             # Fuzzer 모듈 작동
    #             future_fuzzer=executor.submit(
    #                 fuzzer.run,
    #                 base_url    = recon_url,  # 필수
    #                 spider_urls = spider_urls,  # 필수 (없으면 [])
    #                 difficulty  = fuzzer_level,  # 필수: 1(이지) or 2(하드)
    #             )

    #             # 완료되는 순서대로 처리 (as_completed 사용)
    #             from concurrent.futures import as_completed
    #             futures = {future_nmap: "nmap", future_fuzzer: "fuzzer"}
    #             # futures = {future_nmap: "nmap"}
    #             for future in as_completed(futures):
    #                 target = futures[future]
    #                 result = future.result()
                    
    #                 if target == "nmap":
    #                     nmap_data = result
    #                     print("nmap은",result)
    #                     progress.update(task1, advance=1, description="[cyan]✔ Nmap 스캔 완료")
    #                 elif target == "fuzzer":
    #                     fuzzer_data = result
    #                     progress.update(task2, advance=1, description="[magenta]✔ Fuzzer 완료")
        
    #     except Exception as e:
    #         console.print(f"[bold red] KSJ-RECON 실행 중 오류 발생: {e}")
   
    #     # --- 5. Middle Core로 데이터 통합 ---
    #     middle_core_task = progress.add_task("[yellow]모듈 데이터 통합 중...", total=1)
        

    #     mid_core.set_nmap_data(nmap_data)
    #     mid_core.set_fuzzer_data(fuzzer_data)

    #     recon_results = mid_core.get_all_recon_results()
    #     # save_path1 = "C:/Ksj-Recon/KSJ-Recon/output/middle_core_data.txt"
    #     # asyncio.run(save_to_txt(save_path1, recon_results))
    #     # print("Recon 데이터 결과")
    #     # print()
    #     # print(recon_results)
    #     print("모듈 통합 데이터 저장 완료")
    #     progress.update(middle_core_task, advance=1, description="[yellow]✔ 모듈 데이터 통합 완료")
        if recon_mode=="mode_a":
            #reporter = LLMReporter()
            #reporter.generate_dashboard_from_data(recon_results,recon_mode)
            end = time.time()
            final_time=end - start
            # mid_core.set_time(final_time)
            console.print(f"[bold magenta]⏱ 소요 시간:[/] [bold cyan]{end - start:.2f}초[/]")
            pass
        elif recon_mode=="mode_b":
            print("테스트 시작 , mode_b")
            pre_data={
                        "sql_data": {
                            "target_url": "https://hotspotfan.online/",
                            "crawler_data": [
                            {
                                "name": "page",
                                "location": "query",
                                "value": "0"
                            },
                            {
                                "name": "size",
                                "location": "query",
                                "value": "60"
                            },
                            {
                                "name": "sort",
                                "location": "query",
                                "value": "createdAt,desc"
                            },
                            {
                                "name": "position",
                                "location": "query",
                                "value": "MAIN"
                            },
                            {
                                "name": "type",
                                "location": "query",
                                "value": "seller"
                            }
                            ],
                            "auth": {
                            "cookie": "",
                            "Authorization": "",
                            "Referer": "",
                            "Accept-Language": ""
                            },
                            "nmap_data": {
                            "port": "443",
                            "service": "http",
                            "version": ""
                            },
                            "fuzzer_data": [
                            "https://hotspotfan.online/api/orders/me",
                            "https://hotspotfan.online/api/products/:id/comments?page=0&size=20",
                            "https://hotspotfan.online/api/products?page=0&size=60",
                            "https://hotspotfan.online/api/orders/seller/me",
                            "https://hotspotfan.online/api/categories?page=0&size=100",
                            "https://hotspotfan.online/api/follows/my-followers",
                            "https://hotspotfan.online/api/products/:id",
                            "https://hotspotfan.online/api/users/managers/:id",
                            "https://hotspotfan.online/api/auth/refresh",
                            "https://hotspotfan.online/api/ranking/realtime?type=seller",
                            "https://hotspotfan.online/api/ranking/weekly?type=seller",
                            "https://hotspotfan.online/api/follows/followings?size=20",
                            "https://hotspotfan.online/api/ranking/daily?type=seller",
                            "https://hotspotfan.online/api/products?page=0&size=10&sort=createdAt,desc",
                            "https://hotspotfan.online/api/ranking/monthly?type=seller",
                            "https://hotspotfan.online/api/banners?position=MAIN",
                            "https://hotspotfan.online/api/products/:id/likes",
                            "https://hotspotfan.online/api/cart",
                            "https://hotspotfan.online/users/admin/me",
                            "https://hotspotfan.online/manager",
                            "https://hotspotfan.online/products/:id",
                            "https://hotspotfan.online/influencer/:id",
                            "https://hotspotfan.online/search",
                            "https://hotspotfan.online/ranking",
                            "https://hotspotfan.online/orders",
                            "https://hotspotfan.online/seller/upload"
                            ]
                        },
                        "xss_data": {
                            "base_url": "https://hotspotfan.online/",
                            "session_id": "",
                            "token": "",
                            "login_mock_path": "https://hotspotfan.online/auth",
                            "spider_urls": [
                            "https://hotspotfan.online/",
                            "https://hotspotfan.online/auth",
                            "https://hotspotfan.online/search",
                            "https://hotspotfan.online/ranking",
                            "https://hotspotfan.online/products/:id",
                            "https://hotspotfan.online/influencer/:id",
                            "https://hotspotfan.online/seller/upload",
                            "https://hotspotfan.online/me",
                            "https://hotspotfan.online/mypage",
                            "https://hotspotfan.online/users/admin/me",
                            "https://hotspotfan.online/manager",
                            "https://hotspotfan.online/obs/widget",
                            "https://hotspotfan.online/payment/success",
                            "https://hotspotfan.online/payment/fail",
                            "https://hotspotfan.online/orders",
                            "https://hotspotfan.online/cart",
                            "https://hotspotfan.online/follow-list",
                            "https://hotspotfan.online/my-followers",
                            "https://hotspotfan.online/purchase",
                            "https://hotspotfan.online/api/products?page=0&size=60",
                            "https://hotspotfan.online/api/products?page=0&size=10&sort=createdAt,desc",
                            "https://hotspotfan.online/api/categories?page=0&size=100",
                            "https://hotspotfan.online/api/ranking/weekly?type=seller",
                            "https://hotspotfan.online/api/banners?position=MAIN",
                            "https://hotspotfan.online/api/products/:id/comments?page=0&size=20"
                            ],
                            "urls": [
                            {
                                "url": "https://hotspotfan.online/search",
                                "method": "GET",
                                "type": "unknown",
                                "body": {},
                                "fields": {},
                                "safe_to_submit": False,
                                "cookies": {},
                                "headers": {},
                                "priority": "MEDIUM"
                            },
                            {
                                "url": "https://hotspotfan.online/auth",
                                "method": "GET",
                                "type": "form",
                                "body": {},
                                "fields": {
                                "username": "",
                                "password": ""
                                },
                                "safe_to_submit": False,
                                "cookies": {},
                                "headers": {},
                                "priority": "HIGH"
                            },
                            {
                                "url": "https://hotspotfan.online/me",
                                "method": "GET",
                                "type": "form",
                                "body": {},
                                "fields": {
                                "username": "",
                                "password": ""
                                },
                                "safe_to_submit": False,
                                "cookies": {},
                                "headers": {},
                                "priority": "HIGH"
                            },
                            {
                                "url": "https://hotspotfan.online/mypage",
                                "method": "GET",
                                "type": "form",
                                "body": {},
                                "fields": {
                                "username": "",
                                "password": ""
                                },
                                "safe_to_submit": False,
                                "cookies": {},
                                "headers": {},
                                "priority": "HIGH"
                            },
                            {
                                "url": "https://hotspotfan.online/seller/upload",
                                "method": "GET",
                                "type": "form",
                                "body": {},
                                "fields": {
                                "username": "",
                                "password": ""
                                },
                                "safe_to_submit": False,
                                "cookies": {},
                                "headers": {},
                                "priority": "HIGH"
                            },
                            {
                                "url": "https://hotspotfan.online/users/admin/me",
                                "method": "GET",
                                "type": "form",
                                "body": {},
                                "fields": {
                                "username": "",
                                "password": ""
                                },
                                "safe_to_submit": False,
                                "cookies": {},
                                "headers": {},
                                "priority": "HIGH"
                            },
                            {
                                "url": "https://hotspotfan.online/payment/success",
                                "method": "GET",
                                "type": "form",
                                "body": {},
                                "fields": {
                                "username": "",
                                "password": ""
                                },
                                "safe_to_submit": False,
                                "cookies": {},
                                "headers": {},
                                "priority": "MEDIUM"
                            },
                            {
                                "url": "https://hotspotfan.online/api/products?page=0&size=60",
                                "method": "GET",
                                "type": "json",
                                "body": {},
                                "fields": {
                                "page": "0",
                                "size": "60"
                                },
                                "safe_to_submit": False,
                                "cookies": {},
                                "headers": {},
                                "priority": "MEDIUM"
                            },
                            {
                                "url": "https://hotspotfan.online/api/products/:id/comments?page=0&size=20",
                                "method": "GET",
                                "type": "json",
                                "body": {},
                                "fields": {
                                "page": "0",
                                "size": "20"
                                },
                                "safe_to_submit": False,
                                "cookies": {},
                                "headers": {},
                                "priority": "HIGH"
                            },
                            {
                                "url": "https://hotspotfan.online/api/ranking/weekly?type=seller",
                                "method": "GET",
                                "type": "json",
                                "body": {},
                                "fields": {
                                "type": "seller"
                                },
                                "safe_to_submit": False,
                                "cookies": {},
                                "headers": {},
                                "priority": "MEDIUM"
                            }
                            ],
                            "stored_targets": [
                            {
                                "submit_url": "https://hotspotfan.online/seller/upload",
                                "view_url": "https://hotspotfan.online/products/:id",
                                "body": {},
                                "safe_to_submit": False,
                                "cookies": {},
                                "headers": {},
                                "priority": "HIGH"
                            },
                            {
                                "submit_url": "https://hotspotfan.online/api/products?page=0&size=60",
                                "view_url": "https://hotspotfan.online/products/:id",
                                "body": {},
                                "safe_to_submit": False,
                                "cookies": {},
                                "headers": {},
                                "priority": "HIGH"
                            },
                            {
                                "submit_url": "https://hotspotfan.online/api/products/:id/comments?page=0&size=20",
                                "view_url": "https://hotspotfan.online/products/:id",
                                "body": {},
                                "safe_to_submit": False,
                                "cookies": {},
                                "headers": {},
                                "priority": "HIGH"
                            }
                            ],
                            "options": {
                            "browser_verify": True,
                            "stored_xss": True,
                            "dom_hash_xss": True,
                            "dom_stored_xss": False,
                            "timeout": 10,
                            "verify_tls": False
                            },
                            "evidence_dir": "evidence",
                            "results_dir": "results"
                        },
                        "filedown_data": {
                            "target": {
                            "url": "https://hotspotfan.online/api/products?page=0&size=60",
                            "method": "GET",
                            "params": {
                                "page": "0",
                                "size": "60"
                            },
                            "data": {},
                            "headers": {},
                            "inject_params": [
                                "page",
                                "size"
                            ],
                            "timeout": 5.0
                            },
                            "options": {
                            "max_workers": 4,
                            "payload_limit": 3,
                            "timeout": 10.0,
                            "verify": False,
                            "allow_redirects": False,
                            "proxies": {},
                            "user_agent": "KSJ-DAST-Scanner/1.0"
                            }
                        },
                        "ssrf_data": {
                            "target": {
                            "url": "https://hotspotfan.online/api/banners?position=MAIN",
                            "method": "GET",
                            "params": {
                                "position": "MAIN"
                            },
                            "data": {},
                            "headers": {},
                            "inject_params": [
                                "position"
                            ],
                            "timeout": 5.0
                            },
                            "options": {
                            "max_workers": 4,
                            "payload_limit": 3,
                            "timeout": 10.0,
                            "verify": False,
                            "allow_redirects": False,
                            "proxies": {},
                            "user_agent": "KSJ-DAST-Scanner/1.0"
                            }
                        }
                        }
            # preprocess_task = progress.add_task("[bold blue]각 공격 모듈에 맞는 통합 데이터 전처리 중...", total=1)
            # preprocessor = LLMPreprocessor()
            # pre_data = preprocessor.generate_preprocess_data(recon_results)
            # save_path2 = "C:/Ksj-Recon/KSJ-Recon/output/pre_data.txt"
            # asyncio.run(save_to_txt(save_path2, pre_data))
            # print("데이터 전처리끝")
            # print()
            # print(pre_data)
            # progress.update(preprocess_task, advance=1, description="[bold blue]✔ 각 공격 모듈에 맞는 통합 데이터 전처리 완료")
            
            # 공격 모듈에 데이터 넣기
            # sqli_task = progress.add_task("[bold red]SQLi 모듈 동작중...", total=1)
            # sql_data = pre_data["sql_data"]
            # scanInput=ScanInput.from_dict(sql_data)
            # sql_results =(asyncio.run(run_scan(scanInput))).to_json()
            # progress.update(sqli_task, advance=1, description="[bold red]✔ SQLi 모듈 동작 완료[/]")
            # # mid_core.set_sqli_data(sql_results)
            # print("SQLi 모듈", sql_results)
            

            # xss_data = pre_data["xss_data"]
            # xss_results=asyncio.run(run_xss_scan(xss_data))
            # # mid_core.set_xss_data(xss_results)
            # print("XSS 모듈", xss_results)

            
            # fileDownloadModule=FileDownloadModule()
            # # # sSRFModule=SSRFModule()

            # filedown_data = pre_data["filedown_data"]
            # filedownload_results=asyncio.run(FileDownloadModule.run_json(filedown_data))
            # # # mid_core.set_file_download_data(filedownload_results)
            # print("filedownload 모듈", filedownload_results)

            # ssrf_data = pre_data["ssrf_data"]
            # ssrf_results=asyncio.run(SSRFModule.run_json(ssrf_data))
            # # mid_core.set_ssrf_data(ssrf_results)
            # print("에스에스알에프",ssrf_results)
            end = time.time()
            final_time=end - start
            # mid_core.set_time(final_time)
            console.print(f"[bold magenta]⏱ 소요 시간:[/] [bold cyan]{end - start:.2f}초[/]")
            # integrated_results=mid_core.get_integrated_results()
            #reporter = LLMReporter()
            #reporter.generate_dashboard_from_data(integrated_results,recon_mode)
            pass
        

        #report_task = progress.add_task("[bold blue]LLM 기반 보고서 생성 중...", total=1)

        # preprocessor -> core가 받고 -> 공격 모듈에 뿌려주기 -> 모드 B에서만
        #공격 모듈이 데이터 주면 그거를 json으로 통합 ( 형식 디코 확인 ) 후 LLM generate_dashboard_from_data -> mode_a , mode_b 인자로 들어가야함
        #reporter.generate_dashboard_from_data(integrated_results,recon_mode)
        #progress.update(report_task, advance=1, description="[bold blue]✔ LLM 보고서 생성 및 저장 완료")

# 결과물 출력 최적화 (Rich 전용 JSON 출력)
    # console.print(Panel("[bold white]최종 통합 결과 데이터 (JSON)[/bold white]", border_style="yellow"))
    # console.print_json(data=results)
    # console.print("[bold green]Middle_core 테스트 끝[/bold green]")
else:
    console.print("[bold red]✘ Error: URL를 다시 입력하세요.[/bold red]")


 



