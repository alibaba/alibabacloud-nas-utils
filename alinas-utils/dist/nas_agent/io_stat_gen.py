import json

rows = [
    "getattr", "setattr", "lookup", "readlink", "stat", "read", "write",
    "mknod", "remove", "rename", "link", "readdir", "open", "close",
    "batch_remove", "batch_read", "batch_write",
    "cwrite", "cread", "setattr_flush", "create_flush", "remove_flush",
    "rename_flush", "link_flush", "write_flush", "commit"
]

columns = [
    "kqueue", "uqueue", "uprocess", "precheck", "cache", "backend",
    "reply", "rtotal", "rflyout", "rflyin", "rserver", "total",
    "vsc_cqueue", "vsc_squeue", "vsc_blk", "vsc_process", "vsc_total",
    "erpc_cqueue", "erpc_net", "erpc_squeue", "erpc_process", "erpc_squeue2",
    "erpc_net2", "erpc_cqueue2", "erpc_total", "subtask", "subtask2",
    "renew_attr", "uswitch", "lease", "cache_direct", "cache_pre",
    "cache_done", "rpc_retries", "fuse_retries" 
]

idx = 1
configs = []
for row in rows:
    for col in columns:
        configs.append({"name": f"{row}_{col}_time", "index": idx, "type": "compute"})
        idx += 1

# 将每个条目转换为紧凑的JSON字符串（无空格）
compact_entries = [json.dumps(entry, separators=(",", ":"), ensure_ascii=False) for entry in configs]
# 组合为完整的JSON（每个条目独立一行，整体缩进2空格）
formatted_json = "[\n  " + ",\n  ".join(compact_entries) + "\n]"

print(formatted_json)
#print(json.dumps(configs, indent=2))
