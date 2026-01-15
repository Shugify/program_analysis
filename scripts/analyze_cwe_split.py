import json

def get_cwe_from_path(filepath):
    if "CWE190" in filepath:
        return "CWE190"
    elif "CWE369" in filepath:
        return "CWE369"
    return "Other"

def analyze_split(llm_path, codeql_path):
    print("--- Calculating Split Performance (CWE-190 vs CWE-369) ---")
    
    # 1. 统计总数和 LLM 检出数 (基于 LLM 结果文件，因为它包含完整数据集)
    stats = {
        "CWE190": {"total": 0, "llm_hits": 0, "codeql_hits": 0},
        "CWE369": {"total": 0, "llm_hits": 0, "codeql_hits": 0}
    }
    
    with open(llm_path, 'r', encoding='utf-8') as f:
        llm_data = json.load(f)
        
    for item in llm_data:
        path = item.get('file', '')
        cwe = get_cwe_from_path(path)
        
        if cwe in stats:
            stats[cwe]["total"] += 1
            if item.get('llm_prediction') is True:
                stats[cwe]["llm_hits"] += 1
                
    # 2. 统计 CodeQL 检出数 (基于 SARIF)
    with open(codeql_path, 'r', encoding='utf-8') as f:
        sarif_data = json.load(f)
        
    # 用集合去重，确保是 File-Level Recall
    codeql_files = set()
    for res in sarif_data['runs'][0]['results']:
        uri = res['locations'][0]['physicalLocation']['artifactLocation']['uri']
        codeql_files.add(uri)
        
    for uri in codeql_files:
        cwe = get_cwe_from_path(uri)
        if cwe in stats:
            stats[cwe]["codeql_hits"] += 1

    # 3. 输出结果
    print(f"{'CWE Type':<10} | {'Total':<6} | {'CodeQL Hits':<12} | {'CodeQL Recall':<14} | {'LLM Hits':<8} | {'LLM Recall'}")
    print("-" * 80)
    
    for cwe, data in stats.items():
        total = data['total']
        if total == 0: continue
        
        c_recall = (data['codeql_hits'] / total) * 100
        l_recall = (data['llm_hits'] / total) * 100
        
        print(f"{cwe:<10} | {total:<6} | {data['codeql_hits']:<12} | {c_recall:.2f}%{'':<6} | {data['llm_hits']:<8} | {l_recall:.2f}%")

if __name__ == "__main__":
    # 请确保路径正确
    llm_file = "/remote-home/shijiajia/programmer/analysis/final_results/llm_qwen_results.json"
    sarif_file = "/remote-home/shijiajia/programmer/analysis/final_results/codeql_results.sarif"
    
    analyze_split(llm_file, sarif_file)