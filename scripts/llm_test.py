import os
import glob
import json
import random
import time
import re
from openai import OpenAI
from tqdm import tqdm


MODEL_NAME = "qwen2.5-coder:7b"

BASE_URL = "http://localhost:11434/v1"

API_KEY = "ollama"


# 初始化客户端
client = OpenAI(api_key=API_KEY, base_url=BASE_URL)

def get_code_content(filepath):
    """读取 Java 文件内容"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return ""

def clean_json_string(content):
    """
    清洗模型返回的字符串，提取 JSON 部分。
    防止模型返回 ```json ... ``` 格式导致解析失败。
    """
    start = content.find('{')
    end = content.rfind('}')
    if start != -1 and end != -1:
        return content[start:end+1]
    return content

def test_file_with_llm(filepath, cwe_type):
    """发送代码给 LLM 进行检测"""
    code = get_code_content(filepath)
    if not code: return None

    prompt = f"""
    You are a software security expert using static analysis.
    Analyze the following Java code for **{cwe_type}**.
    
    The code comes from the NIST Juliet Test Suite.
    It contains a 'bad()' method (intended to be vulnerable) and 'good()' methods (intended to be safe).
    
    **Task:**
    Determine if the 'bad()' method actually contains a {cwe_type} vulnerability.
    
    **Code:**
    ```java
    {code}
    ```
    
    **Response Requirement:**
    You must respond STRICTLY in valid JSON format, with no extra text.
    Format:
    {{
        "vulnerable": true,
        "confidence": "high/medium/low",
        "reason": "concise explanation of where the overflow or divide-by-zero happens"
    }}
    """

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": "You are a code auditor. Respond ONLY in JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0,
            max_tokens=500
        )
        raw_content = response.choices[0].message.content
        cleaned_content = clean_json_string(raw_content)
        return json.loads(cleaned_content)
        
    except json.JSONDecodeError:
        print(f"\n[Warning] JSON Parse Error for {filepath}. Raw output: {raw_content[:50]}...")
        return {"error": "json_parse_error", "raw": raw_content}
    except Exception as e:
        print(f"\n[Error] API call failed: {e}")
        return {"error": str(e)}

def run_experiment():
    results = []
    
    targets = [
        ("dataset/CWE190_Integer_Overflow", "Integer Overflow (CWE-190)"),
        ("dataset/CWE369_Divide_by_Zero", "Divide by Zero (CWE-369)")
    ]

    print(f"Starting FULL Experiment with model: {MODEL_NAME}")
    print("-" * 50)

    for folder, cwe_name in targets:
        print(f"\nScanning directory: {folder}")
        
        files = glob.glob(f"{folder}/**/*.java", recursive=True)
        
        valid_files = [
            f for f in files 
            if "CWE" in f 
            and "Servlet" not in f 
            and "Abstract" not in f 
            and "Helper" not in f
        ]
        
        if not valid_files:
            print(f"No valid test files found in {folder}. Check path?")
            continue
            
     
        # 使用所有找到的 valid_files
        print(f"Target: {cwe_name} | Files found: {len(valid_files)} | Testing: ALL")

        # 使用 valid_files 变量进行测试
        for filepath in tqdm(valid_files, desc=f"Testing {cwe_name.split(' ')[0]}"):
            llm_result = test_file_with_llm(filepath, cwe_name)
            
            if llm_result:
                record = {
                    "file": filepath,
                    "cwe_type": cwe_name,
                    "ground_truth": "vulnerable",
                    "llm_prediction": llm_result.get("vulnerable"),
                    "llm_reason": llm_result.get("reason"),
                    "raw_response": llm_result
                }
                results.append(record)
    
    output_file = 'llm_full_dataset_results.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
        
    print(f"\nExperiment Finished! Results saved to {output_file}")
    
    total = len(results)
    detected = sum(1 for r in results if r.get("llm_prediction") is True)
    print(f"Total Tested: {total}")
    print(f"Detected Vulnerabilities: {detected}")
    if total > 0:
        print(f"Detection Rate: {detected/total*100:.2f}%")

if __name__ == "__main__":
    run_experiment()