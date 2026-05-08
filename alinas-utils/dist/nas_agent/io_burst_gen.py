import json

rows = [
    "getattr_qps", "setattr_qps", "lookup_qps", "readlink_qps", "stat_qps", "read_qps", "write_qps",
    "mknod_qps", "remove_qps", "rename_qps", "link_qps", "readdir_qps", "open_qps", "close_qps",
    "batch_remove_qps", "batch_read_qps", "batch_write_qps",
    "cwrite_qps", "cread_qps", "setattr_flush_qps", "create_flus_qpsh", "remove_flush_qps",
    "rename_flush_qps", "link_flush_qps", "write_flush_qps", "commit_qps",
    "read_throughput", "write_throughput"
]

columns = [
    "now-1s", "now-2s", "now-3s", "now-4s", "now-5s", "now-6s", "now-7s", "now-8s", "now-9s", "now-10s"
]


idx = 1
configs = []
for row in rows:
    for col in columns:
        configs.append({"name": f"{row}_{col}", "index": idx, "type": "raw-nonzero"})
        idx += 1

# 将每个条目转换为紧凑的JSON字符串（无空格）
compact_entries = [json.dumps(entry, separators=(",", ":"), ensure_ascii=False) for entry in configs]
# 组合为完整的JSON（每个条目独立一行，整体缩进16空格）
formatted_json = "[\n  " + ",\n                ".join(compact_entries) + "\n]"

print(formatted_json)
#print(json.dumps(configs, indent=2))
