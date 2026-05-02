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



#선 Crawler 모듈에서 데이터 받은 후 Fuzzer 모듈로 데이터 전송
#후 Fuzzer 모듈에서 데이터 받아오기



#LLM 기반 보고서 작성 기능






