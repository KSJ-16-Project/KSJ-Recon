# 역할
# Nmap , Crawler , Fuzzer 모듈에서 데이터 받아오기


class Middle_core:

    #초기화 메서드 
    def __init__(self):
        # 클래스 내부 메모리에 데이터를 저장할 딕셔너리 초기화
        self.storage={
            "nmap":None,
            "crawler":None,
            "fuzzer":None
        }
    
    # nmap 모듈에서 데이터 받아 내부 저장소에 기록
    def get_nmap_data(self, nmap_data):
        self.storage["nmap"] = nmap_data


   # crawler 모듈에서 데이터 받아 내부 저장소에 기록
    def get_crawler_data(self, crawler_data):
        self.storage["crawler"] = crawler_data

    
   # fuzzer 모듈에서 데이터 받아 내부 저장소에 기록
    def get_fuzzer_data(self, fuzzer_data):
        self.storage["fuzzer"] = fuzzer_data

    # 저장된 전체 데이터를 확인하거나 다른 모듈(LLM 등)에 전달할 때 사용
    def get_all_results(self):
        #일단은 한개로 합쳤다.
        return self.storage
    
    # 크롤러 데이터에서 Fuzzer 모듈에 줄 URL 리스트 생성
    async def make_url_list(self,final_crawl_data):
        # 1. 모든 페이지 리스트 합치기
        all_pages = final_crawl_data.get('public_pages', []) + final_crawl_data.get('authenticated_pages', [])

        # 2. 각 항목별로 URL 추출하여 집합(set)으로 통합
        urls = set(final_crawl_data.get('sitemap_urls', []))

        for p in all_pages:
            urls.add(p.get('url'))
            urls.update(p.get('links', []) + p.get('routes', []) + p.get('scripts', []))
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






