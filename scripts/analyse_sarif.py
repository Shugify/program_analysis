import json
from collections import Counter

def analyze_sarif(filepath):
    print(f"--- Analyzing CodeQL SARIF: {filepath} ---")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        results = data['runs'][0]['results']
        total_alerts = len(results)
        
        # 统计涉及的文件数 (去重)
        files = set()
        cwe_counts = Counter()

        for res in results:
            # 获取文件路径
            uri = res['locations'][0]['physicalLocation']['artifactLocation']['uri']
            files.add(uri)
            
            # 获取规则ID (通常包含 CWE 信息)
            rule_id = res['ruleId']
            cwe_counts[rule_id] += 1

        print(f"Total Alerts (漏洞实例数): {total_alerts}")
        print(f"Unique Files (检出文件数): {len(files)}")
        print("\n--- Rule/CWE Distribution ---")
        for rule, count in cwe_counts.items():
            print(f"{count:<5} | {rule}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    analyze_sarif("../final_results/codeql_results.sarif") # 确保路径对