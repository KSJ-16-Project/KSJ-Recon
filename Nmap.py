import nmap
import json
# import middleware  # 미들웨어 임포트
from datetime import datetime


class NmapScanner:
    def __init__(self, nmap_path=None):
        if nmap_path:
            self.nm = nmap.PortScanner(nmap_search_path=(nmap_path,))
        else:
            self.nm = nmap.PortScanner()

    def scan(self, target, level=1):
        if (level == 2):
            arguments='-sS -sV --open -p- -T4' # 풀스캔
        else:
            arguments='-sS -sV --open -T4' # 라이트스캔 상위 1000개 포트만
        self.nm.scan(hosts=target, arguments=arguments)
        return self._parse_result(target)

    def _parse_result(self, target):
        result = {
            "target": target,
            "scan_time": datetime.utcnow().isoformat(),
            "hosts": []
        }

        for host in self.nm.all_hosts():
            host_data = {
                "ip": host,
                "status": self.nm[host].state(),
                "ports": []
            }

            for proto in self.nm[host].all_protocols():
                for port in self.nm[host][proto]:
                    port_data = self.nm[host][proto][port]

                    normalized = {
                        "port": port,
                        "protocol": proto,
                        "state": port_data.get("state"),
                        "service": port_data.get("name"),
                        "product": port_data.get("product"),
                        "version": port_data.get("version"),
                        "extra_info": port_data.get("extrainfo"),
                        "cpe": port_data.get("cpe")
                    }

                    host_data["ports"].append(normalized)

            result["hosts"].append(host_data)

        return self.connect_middle(result) # 미들 미구현으로인해서 현재는 정상동작 안함
    
    # 연동부 임시 함수들로 구현했습니다
    def connect_middle(self, data):
        conn = middleware()
        conn.middlefunc(data)


    def save_json(self, data, filename="nmap_result.json"):
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)


# ======================
# 실행부 코드 메인로직쪽에 구현해주시면 돌아 갈것 같아용
# ======================
''' 임시 주석
if __name__ == "__main__":
    scanner = NmapScanner()  # 필요하면 nmap 경로 수동지정

    data = scanner.scan("gym.contentshub.kr")

    scanner.save_json(data)

    print("[+] JSON 결과 생성 완료")
'''