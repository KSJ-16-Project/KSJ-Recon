#nmap 모듈에서 데이터 받아오기
def get_nmap_data(nmap_data):
    print("receive data",nmap_data)

# crawler 모듈에서 데이터 받아오기
def get_crawler_data(crawler_data):
    print("receive data",crawler_data)

# Fuzzer 모듈에서 데이터 받아오기
def get_Fuzzer_data(fuzzer_data):
    print("receive data",fuzzer_data)

class Middle_core:
    #초기화 메서드 
    def __init__(self):
        return
    
    # 메서드 #
    ############### Nmap 모듈 쪽 ###################
    # 메서드 ( 동작 정의 )
    # nmap 모듈에서 데이터 받아오기
    def get_nmap_data(nmap_data):
        print("receive data",nmap_data)
    
    ############## Crawler 모듈 쪽 ####################

    # 메서드 ( 동작 정의 )
    # crawler 모듈에서 데이터 받아오기
    def get_crawler_data(crawler_data):
        print("receive data",crawler_data)

    # 메서드 ( 동작 정의 )
    # Fuzzer 모듈에서 데이터 받아오기
    def get_Fuzzer_data(fuzzer_data):
        print("receive data",fuzzer_data)


    ############### Fuzzer 모듈 쪽 #################
    


#선 Crawler 모듈에서 데이터 받은 후 Fuzzer 모듈로 데이터 전송
#후 Fuzzer 모듈에서 데이터 받아오기



#LLM 기반 보고서 작성 기능






