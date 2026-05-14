# 역할
# Nmap , Crawler , Fuzzer 모듈에서 데이터 받아오기
import os
import json

class Middle_core:

    #초기화 메서드 
    def __init__(self,target_url):
        # 1. 경로 설정 (KSJ-RECON/output/ 폴더)
        current_file = os.path.abspath(__file__)
        self.project_root = os.path.dirname(os.path.dirname(current_file))
        self.output_dir = os.path.join(self.project_root, "output")
        os.makedirs(self.output_dir, exist_ok=True)
    
        # 저장될 파일 이름
        self.save_path_recon = os.path.join(self.output_dir, "recon_report.json")
        self.save_path_senario = os.path.join(self.output_dir, "attack_senario.json")
        # 클래스 내부 메모리에 데이터를 저장할 딕셔너리 초기화
        
        # 정찰 모듈 통합 데이터
        self.Recon_storage={
            "nmap":None,
            "crawler":None,
            "fuzzer":None
        }

        # 공격 모듈 통합 데이터
        self.Attack_storage={
            "sqli": None,
            "xss": None,
            "file_download": None,
            "ssrf": None
        }

        # LLM 기반 공격시나리오 생성 모듈에 전달할 통합 데이터
        self.Integrated_storage = {
            "scan": self.Recon_storage,
            "attacks": self.Attack_storage,
            "metadata": {
                "target": target_url,
                "scan_time": None
            }
        }

    def save_recon_file(self):
        """Recon_storage 바구니 그대로 파일로 저장"""
        try:
            with open(self.save_path_recon, 'w', encoding='utf-8') as f:
                json.dump(self.Recon_storage, f, ensure_ascii=False, indent=4)
            return True
        except Exception as e:
            print(f"Recon 파일 저장 오류: {e}")
            return False
        
    def save_senario_file(self):
        """시나리오 생성"""
        try:
            with open(self.save_path_senario, 'w', encoding='utf-8') as f:
                json.dump(self.Integrated_storage, f, ensure_ascii=False, indent=4)
            return True
        except Exception as e:
            print(f"공격 시나리오 파일 저장 오류: {e}")
            return False
        
    # nmap 모듈에서 데이터 받아 내부 저장소에 기록
    def set_nmap_data(self, nmap_data):
        self.Recon_storage["nmap"] = nmap_data

   # crawler 모듈에서 데이터 받아 내부 저장소에 기록
    def set_crawler_data(self, crawler_data):
        self.Recon_storage["crawler"] = crawler_data
       
    
   # fuzzer 모듈에서 데이터 받아 내부 저장소에 기록
    def set_fuzzer_data(self, fuzzer_data):
        self.Recon_storage["fuzzer"] = fuzzer_data
      

    # sqli 모듈에서 데이터 받아 내부 저장소에 기록
    def set_sqli_data(self,sqli_data):
        self.Attack_storage["sqli"] = sqli_data


   # xss 모듈에서 데이터 받아 내부 저장소에 기록
    def set_xss_data(self, xss_data):
        self.Attack_storage["xss"] = xss_data

    
   # file_download 모듈에서 데이터 받아 내부 저장소에 기록
    def set_file_download_data(self, file_download_data):
        self.Attack_storage["file_download"] = file_download_data

    # ssrf 모듈에서 데이터 받아 내부 저장소에 기록
    def set_ssrf_data(self,ssrf_data):
        self.Attack_storage["ssrf"] = ssrf_data

    # 메타 데이터에 시간 설정
    def set_time(self,time_data):
        self.Integrated_storage["metadata"]["scan_time"] = time_data
    
    def get_all_recon_results(self):
        self.save_recon_file()
        return self.Recon_storage
    
    def get_all_attack_results(self):
        return self.Attack_storage

    def get_integrated_results(self):
        self.save_senario_file()
        return self.Integrated_storage
    
    # 크롤러 데이터에서 Fuzzer 모듈에 줄 URL 리스트 생성
    async def make_url_list(self,final_crawl_data):
        # 1. 모든 페이지 리스트 합치기
        all_pages = final_crawl_data.get('public_pages', []) + final_crawl_data.get('authenticated_pages', [])

        # 2. 각 항목별로 URL 추출하여 집합(set)으로 통합
        urls = set(final_crawl_data.get('sitemap_urls', []))

        for p in all_pages:
            urls.add(p.get('url'))
            urls.update(p.get('links', []) + p.get('routes', []))
            urls.update(f.get('action') for f in p.get('forms', []) if f.get('action'))
            urls.update(x.get('url') for x in p.get('xhr_list', []) if isinstance(x, dict) and x.get('url'))

        # 3. 엔드포인트 힌트 추가
        urls.update(h.get('url') for h in final_crawl_data.get('endpoint_hints', []) if h.get('url'))

        # 4. 빈 값 제거 및 리스트화
        final_list = [u for u in urls if u]
        
        return final_list


#선 Crawler 모듈에서 데이터 받은 후 Fuzzer 모듈로 데이터 전송
#후 Fuzzer 모듈에서 데이터 받아오기



#LLM 기반 보고서 작성 기능






