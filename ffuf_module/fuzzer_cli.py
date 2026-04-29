def run_all(config: dict):
    base_url    = config["base_url"]
    tld1        = config["tld1"]
    difficulty  = config["difficulty"]
    spider_urls = config["spider_urls"]

    RESULTS_DIR.mkdir(exist_ok=True)

    # ── 공통 저장 폴더 미리 생성 ──
    from urllib.parse import urlparse
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    host        = urlparse(base_url).netloc or base_url
    safe_host   = "".join(c if c.isalnum() or c in "-_" else "_" for c in host)
    run_dir     = RESULTS_DIR / f"{safe_host}_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    all_results = []
    step_total  = 2 + len(spider_urls)
    step        = 0

    # ── 1. base URL 디렉터리 퍼징 ──
    step += 1
    print(f"[{step}/{step_total}] 디렉터리 퍼징: {base_url}")
    print("-" * 50)

    fuzzer1 = AggressiveFuzzer(base_url)
    result1 = fuzzer1.run_fuzz(
        mode="directory",
        difficulty=difficulty,
        spider_url_count=len(spider_urls),
        save_to=str(run_dir / "fuzzer_directory.json"),  # ← 변경
        verbose=True,
    )
    print_result(result1)
    all_results.append(result1)

    # ── 2. 서브도메인 퍼징 ──
    step += 1
    subdomain_target = f"https://{tld1}"
    print(f"\n[{step}/{step_total}] 서브도메인 퍼징: {subdomain_target}")
    print("-" * 50)

    fuzzer2 = AggressiveFuzzer(subdomain_target)
    result2 = fuzzer2.run_fuzz(
        mode="subdomain",
        difficulty=difficulty,
        save_to=str(run_dir / "fuzzer_subdomain.json"),  # ← 변경
        verbose=True,
    )
    print_result(result2)
    all_results.append(result2)

    # ── 3. Spider URL 퍼징 ──
    for i, url in enumerate(spider_urls, 1):
        step += 1
        print(f"\n[{step}/{step_total}] Spider URL 퍼징: {url}")
        print("-" * 50)

        fuzzer3 = AggressiveFuzzer(url)
        result3 = fuzzer3.run_fuzz(
            mode="directory",
            difficulty=difficulty,
            spider_url_count=len(spider_urls),
            save_to=str(run_dir / f"fuzzer_spider_{i}.json"),  # ← 변경
            verbose=True,
        )
        print_result(result3)
        all_results.append(result3)

    # ── 전체 결과 통합 저장 ──
    save_path = run_dir / "fuzzer_all.json"  # ← 같은 폴더에 저장

    with open(save_path, "w", encoding="utf-8") as f:
        json.dump({
            "base_url":    base_url,
            "tld1":        tld1,
            "difficulty":  difficulty,
            "spider_urls": spider_urls,
            "timestamp":   datetime.now().isoformat(),
            "results":     all_results,
        }, f, indent=2, ensure_ascii=False)

    # 최종 요약
    total_found = sum(len(r.get("results", [])) for r in all_results)
    total_high  = sum(
        len([x for x in r.get("results", []) if x.get("risk") == "HIGH"])
        for r in all_results
    )

    print(f"\n{'=' * 60}")
    print(f"  전체 퍼징 완료")
    print(f"  총 발견:   {total_found}개")
    print(f"  고위험:    {total_high}개")
    print(f"  통합 저장: {save_path}")
    print(f"{'=' * 60}")