
```
├── final_results/                   # [核心证据] 各工具的最终检测结果文件
│   ├── llm_qwen_results.json        # Qwen-Coder 模型的推理结果 (包含 reason 字段)
│   ├── codeql_results.sarif         # CodeQL 的扫描报告 (标准 SARIF 格式)
│   ├── spotbugs_report.xml          # SpotBugs 的扫描报告 (XML 格式)
│   └── infer_report.txt             # Infer 的扫描日志 (TXT 格式)
├── queries/                         # CodeQL 自定义查询规则
│   └── FindArithmeticVulnerabilities.ql  # 本文中编写的污点分析 QL 脚本
└── scripts/                         # 实验自动化与数据分析脚本
    ├── llm_test.py                  # LLM 自动化批量测试脚本
    ├── analyze_cwe_split.py         # 论文表2：计算 CWE-190 与 CWE-369 分项数据的脚本
    ├── analyse_sarif.py             # 论文表1：解析 CodeQL 结果并统计警报数的脚本
    └── analyse_llm.py               # 辅助脚本：分析 LLM 推理关键词


```

