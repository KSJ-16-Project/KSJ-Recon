import subprocess
import platform
import json
from datetime import datetime
import xml.etree.ElementTree as ET
import os
from urllib.parse import urlparse
#import 미들웨어

class NmapScanner:
    def __init__(self, nmap_path=None):
        self.nmap_path = self._get_nmap_path(nmap_path)

    def _get_nmap_path(self, custom_path):
        os_type = platform.system()

        if os_type == "Windows":
            # ../bin/win/ 경로 기준 프로젝트 파일에서 경로변경시 수정 필요
            base_dir = os.path.dirname(os.path.abspath(__file__))
            return os.path.abspath(os.path.join(base_dir, "bin/win/nmap.exe"))

        elif os_type == "Linux": # 다른 OS버전은 추후 개선 예정
            # TODO: 나중에 구현
            return None

        else:
            raise Exception(f"Unsupported OS: {os_type}") # OS 식별 에러처리

    def scan(self, target, level=2):
        if not self.nmap_path:
            raise Exception("Nmap path not configured for this OS")

        if level == 1: # 레벨처리구문 기본값 1 : 라이트스캔
            arguments = ['-sS', '-sV', '--open', '-p-', '-T4']
        else:
            arguments = ['-sS', '-sV', '--open', '-T4']

        cmd = [
            self.nmap_path,
            *arguments,
            "-oX", "-",  # XML stdout
            target
        ]

        print(f"[+] Running Nmap: {' '.join(cmd)}")

        bin_dir = os.path.dirname(self.nmap_path)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=bin_dir,
                timeout=1800  # 풀스캔 최대 대기시간, 필요시 조정
            )

            if result.returncode != 0:
                return {
                    "target": target,
                    "scan_time": datetime.utcnow().isoformat(),
                    "status": "failed",
                    "error": result.stderr,
                    "hosts": []
                }

            return self._parse_result(target, result.stdout)

        except subprocess.TimeoutExpired:
            return {
                "target": target,
                "scan_time": datetime.utcnow().isoformat(),
                "status": "timeout",
                "error": "Nmap scan timed out",
                "hosts": []
            }

        except KeyboardInterrupt:
            return {
                "target": target,
                "scan_time": datetime.utcnow().isoformat(),
                "status": "interrupted",
                "error": "Scan interrupted by user",
                "hosts": []
            }

    def _parse_result(self, target, xml_data):
        root = ET.fromstring(xml_data)

        result = {
            "target": target,
            "scan_time": datetime.utcnow().isoformat(),
            "hosts": []
        }

        for host in root.findall("host"):
            status_elem = host.find("status")
            status = status_elem.get("state") if status_elem is not None else ""
            # LLM 전달용 None 값 String 변환 작업
            address_elem = host.find("address")
            address = address_elem.get("addr") if address_elem is not None else ""

            host_data = {
                "ip": address,
                "status": status,
                "ports": []
            }

            ports = host.find("ports")
            if ports is None:
                result["hosts"].append(host_data)
                continue

            for port in ports.findall("port"):
                port_id = int(port.get("portid")) if port.get("portid") else 0
                protocol = port.get("protocol") or ""

                state_elem = port.find("state")
                state = state_elem.get("state") if state_elem is not None else ""

                service_elem = port.find("service")

                service = service_elem.get("name") if service_elem is not None else ""
                product = service_elem.get("product") if service_elem is not None else ""
                version = service_elem.get("version") if service_elem is not None else ""
                extrainfo = service_elem.get("extrainfo") if service_elem is not None else ""

                cpe_list = [
                    c.text.strip()
                    for c in port.findall("service/cpe")
                    if c.text and c.text.strip()
                ]

                normalized = {
                    "port": port_id,
                    "protocol": protocol,
                    "state": state,
                    "service": service or "",
                    "product": product or "",
                    "version": version or "",
                    "extra_info": extrainfo or "",
                    "cpe": cpe_list
                }

                host_data["ports"].append(normalized)

            result["hosts"].append(host_data)

        return result #추후 미들웨어 연동시 connect_middle 함수로 리턴예정

    # 연동부 미들 구현시 함수명 맞추겠슴당
    '''
    def connect_middle(self, data):
        conn = middleware()
        conn.middlefunc(data)

    def save_json(self, data, filename="nmap_result.json"):
        with open(filename, "w") as f:
            json.dump(data, f, indent=4) # 
    '''


# ======================
# 실행부 코어에서 실행시 참고해주세요!
# ======================
'''
if __name__ == "__main__":
    scanner = NmapScanner()

    data = scanner.scan("127.0.0.1",2)
    #scanner.save_json(data)

    print("[+] JSON 결과 생성 완료")
    print("데이타 :",data)
'''