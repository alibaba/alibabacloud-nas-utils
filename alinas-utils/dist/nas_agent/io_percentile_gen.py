import json
from io_gen_common import op_name, metric_name

percentiles = ['p99', 'p90']

idx = 1
configs = []
for percentile in percentiles:
    for row in op_name:
        for col in metric_name:
            configs.append({"name": f"{row}_{col}_time_{percentile}", "index": idx, "type": "raw-nonzero"})
            idx += 1

# 将每个条目转换为紧凑的JSON字符串（无空格）
compact_entries = [json.dumps(entry, separators=(",", ":"), ensure_ascii=False) for entry in configs]
# 组合为完整的JSON（每个条目独立一行，整体缩进16空格）
formatted_json = "[\n  " + ",\n                ".join(compact_entries) + "\n]"

print(formatted_json)
#print(json.dumps(configs, indent=2))
