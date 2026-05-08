import sys
import os

# 프로젝트 루트(KSJ-Recon/)를 sys.path에 추가해 ksj_login 패키지를 올바르게 임포트한다.
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _root not in sys.path:
    sys.path.insert(0, _root)

from xss_module.xss_scanner import main

if __name__ == "__main__":
    main()
