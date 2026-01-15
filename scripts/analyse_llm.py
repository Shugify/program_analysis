import json

def analyze_llm_reasoning(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # 只分析检出为 True 的样本
    true_positives = [d for d in data if d.get('llm_prediction') is True]
    total_tp = len(true_positives)
    
    keywords = {
        "overflow": 0,
        "divide by zero": 0,
        "check": 0,  # 检查是否提到了 "missing check"
        "database": 0,
        "tcp": 0,
        "console": 0
    }
    
    for item in true_positives:
        reason = item.get('llm_reason', '').lower()
        for k in keywords:
            if k in reason:
                keywords[k] += 1
                
    print(f"Total True Positives: {total_tp}")
    print("--- Keyword Frequency in Reasoning ---")
    for k, v in keywords.items():
        print(f"{k}: {v} ({v/total_tp*100:.2f}%)")

if __name__ == "__main__":
    analyze_llm_reasoning("/remote-home/shijiajia/programmer/analysis/final_results/llm_qwen_results.json")