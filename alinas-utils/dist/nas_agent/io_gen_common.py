# if change, modify efc_p90_p99_io_latency and op_latency both
op_name = [
    "getattr", "setattr", "lookup", "readlink", "stat", "read", "write",
    "mknod", "remove", "rename", "link", "readdir", "open", "close",
    "batch_remove", "batch_read", "batch_write",
    "cwrite", "cread", "setattr_flush", "create_flush", "remove_flush",
    "rename_flush", "link_flush", "write_flush", "commit"
]

metric_name = [
    "kqueue", "uqueue", "uprocess", "precheck", "cache", "backend",
    "reply", "rtotal", "rflyout", "rflyin", "rserver", "total",
    "vsc_cqueue", "vsc_squeue", "vsc_blk", "vsc_process", "vsc_total",
    "erpc_cqueue", "erpc_net", "erpc_squeue", "erpc_process", "erpc_squeue2",
    "erpc_net2", "erpc_cqueue2", "erpc_total", "subtask", "subtask2",
    "renew_attr", "uswitch", "lease", "cache_direct", "cache_pre",
    "cache_done", "rpc_retries", "fuse_retries", "tiering_up", "tiering_rserver", "tiering_rtotal", "tiering_fuse_retries"
]