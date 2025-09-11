# coding=utf-8
# python 3.11.12
import argparse
import concurrent
import os
import stat
import sys
import threading
import time
from concurrent import futures
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from logging.handlers import RotatingFileHandler
from multiprocessing import Manager
from queue import Queue
from stat import S_ISREG, S_ISDIR

TOOL_VERSION = "1.0"
INODE_LIST = 'inode_list'
DIR_TREE = 'dir_tree'
ALL = 'all'
REGULAR_FILE = 'regular_file'
DIR = 'dir'
VALID_TYPES = [INODE_LIST, DIR_TREE]
VALID_FILTER_INODE_TYPES = [ALL, REGULAR_FILE, DIR]
BATCH_LINES = 10000
thread_pool = None


class DirectoryStats:
    def __init__(self, args, _stat):
        self.item_count = 0
        self.item_size = 0
        self.skipped_item_count = 0
        if args is not None:
            if _stat is not None:
                if args.use_atime:
                    self.atime = _stat.st_atime
                if args.use_mtime:
                    self.mtime = _stat.st_mtime
                if args.use_ctime:
                    self.ctime = _stat.st_ctime
                if args.use_inode:
                    self.inode = int(_stat.st_ino)
            if args.use_all_inode_num:
                self.all_inode_num = 0
            if args.use_all_size:
                self.all_size = 0

    def add_item_count(self, size):
        self.item_count += size

    def add_item_size(self, size):
        self.item_size += size

    def add_skipped_item_count(self, size):
        self.skipped_item_count += size

    def add_all_inode_num(self, size):
        if self.all_inode_num is None:
            self.all_inode_num = 0
        self.all_inode_num += size

    def add_all_size(self, size):
        if self.all_size is None:
            self.all_size = 0
        self.all_size += size

    def __repr__(self):
        return (f"DirectoryStats(item_count={self.item_count}, "
                f"item_size={self.item_size}, skipped_item_count={self.skipped_item_count})")


class DirectoryStatMap:
    def __init__(self):
        self.directory_map = {}
        self.inode_num = 0
        self.wait_walk_dir_list = []

    def get_or_create(self, directory, args, _stat):
        if directory not in self.directory_map:
            if _stat is None:
                try:
                    _stat = os.lstat(directory)
                except:
                    pass
            self.directory_map[directory] = DirectoryStats(args, _stat)
        return self.directory_map[directory]

    def add_inode_num(self, num):
        self.inode_num += num

    def add_wait_walk_dir(self, directory):
        self.wait_walk_dir_list.append(directory)


def output_timestamp(args, timestamp, with_ms=False):
    if args.human_readable:
        return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(timestamp))
    if with_ms:
        return int(timestamp * 1000)
    return int(timestamp)


def output_bytes(args, num_bytes):
    if args.human_readable:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']:
            if abs(num_bytes) < 1024.0:
                return f"{num_bytes:3.1f}{unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.1f}YB"
    return num_bytes


def format_output_line(args, item_path, _stat=None, dir_stat=None):
    try:
        output_parts = []
        for field in args.output_format_list:
            try:
                if args.stat_type == INODE_LIST:
                    if field == 'path':
                        if args.output_without_prefix:
                            output_parts.append(item_path.replace(args.output_without_prefix, ''))
                        else:
                            output_parts.append(item_path)
                    elif field == 'size':
                        output_parts.append(
                            output_bytes(args,
                                         _stat.st_size if args.use_file_size else _stat.st_blocks * args.block_size))
                    elif field == 'raw_size':
                        output_parts.append(_stat.st_size if args.use_file_size else _stat.st_blocks * args.block_size)
                    elif field == 'inode':
                        output_parts.append(_stat.st_ino)
                    elif field == 'atime':
                        output_parts.append(output_timestamp(args, _stat.st_atime))
                    elif field == 'mtime':
                        output_parts.append(output_timestamp(args, _stat.st_mtime))
                    elif field == 'ctime':
                        output_parts.append(output_timestamp(args, _stat.st_ctime))
                    elif field == 'atime_ms':
                        output_parts.append(output_timestamp(args, _stat.st_atime, True))
                    elif field == 'mtime_ms':
                        output_parts.append(output_timestamp(args, _stat.st_mtime, True))
                    elif field == 'ctime_ms':
                        output_parts.append(output_timestamp(args, _stat.st_ctime, True))
                elif args.stat_type == DIR_TREE:
                    if field == 'path':
                        if args.output_without_prefix:
                            output_parts.append(item_path.replace(args.output_without_prefix, ''))
                        else:
                            output_parts.append(item_path)
                    elif field == 'inode_num':
                        output_parts.append(dir_stat.item_count)
                    elif field == 'size':
                        output_parts.append(output_bytes(args, dir_stat.item_size if (
                            args.use_file_size) else dir_stat.item_size * args.block_size))
                    elif field == 'raw_size':
                        output_parts.append(
                            dir_stat.item_size if args.use_file_size else dir_stat.item_size * args.block_size)
                    elif field == 'skip_num':
                        output_parts.append(dir_stat.skipped_item_count)
                    elif field == 'inode':
                        output_parts.append(dir_stat.inode)
                    elif field == 'atime':
                        output_parts.append(output_timestamp(args, dir_stat.atime))
                    elif field == 'mtime':
                        output_parts.append(output_timestamp(args, dir_stat.mtime))
                    elif field == 'ctime':
                        output_parts.append(output_timestamp(args, dir_stat.ctime))
                    elif field == 'atime_ms':
                        output_parts.append(output_timestamp(args, dir_stat.atime, True))
                    elif field == 'mtime_ms':
                        output_parts.append(output_timestamp(args, dir_stat.mtime, True))
                    elif field == 'ctime_ms':
                        output_parts.append(output_timestamp(args, dir_stat.ctime, True))
                    elif field == 'all_inode_num':
                        output_parts.append(dir_stat.all_inode_num)
                    elif field == 'all_size':
                        output_parts.append(output_bytes(args, dir_stat.all_size if (
                            args.use_file_size) else dir_stat.all_size * args.block_size))
            except Exception as e:
                print(f"Error formatting output line: {e}")
                output_parts.append('')
        if output_parts:
            output_parts = [str(part) for part in output_parts]
            return ','.join(output_parts) + '\n'
        return ''
    except Exception as e:
        print(f"Error formatting output line: {e}")
        return ''


def inode_stat_print(args, local_dir_stat_map, item_path=None, _stat=None, thread_local_output_lines=None):
    if thread_local_output_lines is None:
        thread_local_output_lines = []
    if args.stat_type == INODE_LIST:
        thread_local_output_lines.append(format_output_line(args, item_path, _stat=_stat))
        if len(thread_local_output_lines) >= BATCH_LINES:
            output_stat_lines(args, local_dir_stat_map, thread_local_output_lines)


def dir_stat_map_print(args, dir_stat_map, output_handle, print_elapsed_time=False, clear_screen=False):
    try:
        if clear_screen:
            os.system('cls' if os.name == 'nt' else 'clear')
        function_local_output_lines = []
        for iter_dir_path, iter_dir_stat in sorted(dir_stat_map.directory_map.items()):
            function_local_output_lines.append(format_output_line(args, iter_dir_path, dir_stat=iter_dir_stat))

            if len(function_local_output_lines) >= BATCH_LINES:
                with args.m_output_file_lock:
                    output_handle.writelines(function_local_output_lines)
                    function_local_output_lines.clear()

        with args.m_output_file_lock:
            output_handle.writelines(function_local_output_lines)
            function_local_output_lines.clear()
            if print_elapsed_time:
                end_time = time.time()
                elapsed_time = end_time - args.start_time
                output_handle.write(f"Elapsed time: {elapsed_time} seconds\n")
    except Exception as e:
        print(f"Error printing directory statistics: {e}")


def output_total_line_print(args, dir_stat_map, output_handle, print_elapsed_time=False, clear_screen=False):
    if clear_screen:
        os.system('cls' if os.name == 'nt' else 'clear')
    with args.m_output_file_lock:
        output_handle.write(f"Output total lines: {dir_stat_map.inode_num}\n")
        if print_elapsed_time:
            end_time = time.time()
            elapsed_time = end_time - args.start_time
            output_handle.write(f"Elapsed time: {elapsed_time} seconds\n")


def stat_print_at_runtime(args, dir_stat_map, output_handle, print_elapsed_time=False):
    time.sleep(args.print_process_time)
    while not args.stat_finish:
        if args.stat_type == DIR_TREE:
            dir_stat_map_print(args, dir_stat_map, output_handle, print_elapsed_time, clear_screen=True)
        elif args.stat_type == INODE_LIST:
            output_total_line_print(args, dir_stat_map, output_handle, print_elapsed_time, clear_screen=True)
        else:
            break
        time.sleep(args.print_process_time)


def filter_inode(args, _stat):
    if args.min_size and _stat.st_size < args.min_size:
        return False
    if args.max_size and _stat.st_size > args.max_size:
        return False
    if args.atime and _stat.st_atime > args.atime:
        return False
    if args.atime_after and _stat.st_atime < args.atime_after:
        return False
    if args.mtime and _stat.st_mtime > args.mtime:
        return False
    if args.mtime_after and _stat.st_mtime < args.mtime_after:
        return False
    if args.ctime and _stat.st_ctime > args.ctime:
        return False
    if args.ctime_after and _stat.st_ctime < args.ctime_after:
        return False
    if args.filter_inode_type != ALL:
        if args.filter_inode_type == REGULAR_FILE and not S_ISREG(_stat.st_mode):
            return False
        if args.filter_inode_type == DIR and not S_ISDIR(_stat.st_mode):
            return False

    return True


class CustomArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.common_group = self.add_argument_group('Common arguments')
        self.common_group.add_argument("-t", "--type", dest="stat_type", required=True, choices=VALID_TYPES,
                                       help="supported types : " + ','.join(VALID_TYPES))
        self.common_group.add_argument("-i", "--input", dest="input", required=True,
                                       help="the input directories, split by comma")
        self.common_group.add_argument("--input-from-file", dest="input_from_file", action="store_true",
                                       help="read input dir from a file, one line one input dir")
        self.common_group.add_argument("-o", "--output-path", dest="output_path",
                                       default="/tmp/nas_stat_util.output", help="the output path")
        self.common_group.add_argument("--human", dest="human_readable", action="store_true",
                                       help="print human readable size")
        self.common_group.add_argument("--processes", dest="processes", type=int,
                                       default=10, help="the stat process concurrency")
        self.common_group.add_argument("--threads", dest="threads", type=int, default=10,
                                       help="the stat threads concurrency")
        self.common_group.add_argument("--backup-count", dest="backup_count", type=int, default=9,
                                       help="output backup count")
        self.common_group.add_argument("--print-process-time", dest="print_process_time", type=int, default=0,
                                       help="print process time (seconds)")
        self.common_group.add_argument("--exclude-dirs", dest="exclude_dirs", help="exclude dir names, split by comma")
        self.common_group.add_argument("--exclude-full-path-dirs", dest="exclude_full_path_dirs",
                                       help="exclude full dir paths, split by comma")
        self.common_group.add_argument("--output-format", dest="output_format",
                                       help="Output format each line,"
                                            " type file default: path,size."
                                            " Available choices is: [path,size,inode,atime,mtime,ctime]."
                                            " type dir default: path,inode_num,size,skip_num."
                                            " Available choices is: [path,inode_num,size,skip_num,inode,atime,mtime,ctime,all_inode_num,all_size]."
                                       )
        self.common_group.add_argument("--output-without-head", dest="output_without_header", action='store_true',
                                       help="output file without head line")
        self.common_group.add_argument("--output-without-prefix", dest="output_without_prefix", default='',
                                       help="output path without prefix")
        self.common_group.add_argument("--use-file-size", dest="use_file_size", action='store_true',
                                       help="output file size instead of disk usage")
        self.common_group.add_argument("--block-size", dest="block_size", type=int, default=512,
                                       help="file block size in storage, Usually 512 bytes")
        self.common_group.add_argument("-s", "--min-size", dest="min_size", type=int,
                                       help="Files whose size is bigger than this value, unit: byte")
        self.common_group.add_argument("--max-size", dest="max_size", type=int,
                                       help="Files whose size is smaller than this value, unit: byte")
        self.common_group.add_argument("-a", "--atime", dest="atime", type=int,
                                       help="Files whose access time is earlier than this value")
        self.common_group.add_argument("--atime-after", dest="atime_after", type=int,
                                       help="Files whose access time is later than this value")
        self.common_group.add_argument("-m", "--mtime", dest="mtime", type=int,
                                       help="Files whose modify time is earlier than this value")
        self.common_group.add_argument("--mtime-after", dest="mtime_after", type=int,
                                       help="Files whose modify time is later than this value")
        self.common_group.add_argument("-c", "--ctime", dest="ctime", type=int,
                                       help="Files whose change time is earlier than this value")
        self.common_group.add_argument("--ctime-after", dest="ctime_after", type=int,
                                       help="Files whose change time is later than this value")
        self.common_group.add_argument("--filter-inode-type", dest="filter_inode_type",
                                       choices=VALID_FILTER_INODE_TYPES, default=ALL,
                                       help=f"filter inode type, supported types : {VALID_FILTER_INODE_TYPES}, default: all")

        self.type_dir_group = self.add_argument_group('type dir_tree arguments')
        self.type_dir_group.add_argument("-d", "--depth", dest="depth", type=int, default=2,
                                         help="max depth of show dirs")

        self.type_file_group = self.add_argument_group('type file arguments')


def add_dir_stat_map(args, sum_dir_stat_map, local_dir_stat_map):
    if sum_dir_stat_map is None or local_dir_stat_map is None:
        return
    if local_dir_stat_map.directory_map is not None:
        for iter_dir_path, iter_dir_stat in local_dir_stat_map.directory_map.items():
            if iter_dir_path not in sum_dir_stat_map.directory_map:
                sum_dir_stat_map.directory_map[iter_dir_path] = iter_dir_stat
            else:
                dir_stat = sum_dir_stat_map.directory_map[iter_dir_path]
                dir_stat.add_item_count(iter_dir_stat.item_count)
                dir_stat.add_item_size(iter_dir_stat.item_size)
                dir_stat.add_skipped_item_count(iter_dir_stat.skipped_item_count)
                if args.use_all_inode_num:
                    dir_stat.add_all_inode_num(iter_dir_stat.all_inode_num)
                if args.use_all_size:
                    dir_stat.add_all_size(iter_dir_stat.all_size)
    if local_dir_stat_map.inode_num is not None:
        sum_dir_stat_map.add_inode_num(local_dir_stat_map.inode_num)
    if local_dir_stat_map.wait_walk_dir_list is not None:
        sum_dir_stat_map.wait_walk_dir_list.extend(local_dir_stat_map.wait_walk_dir_list)


def stat_process(args, dir_list):
    global thread_pool
    if not thread_pool:
        thread_pool = ThreadPoolExecutor(max_workers=args.threads)
    args.thread_lock = threading.Lock()
    process_dir_stat_map = DirectoryStatMap()
    args.process_wait_queue_size = args.m_process_wait_queue.qsize()
    args.thread_future_set = set()
    args.thread_wait_queue = Queue()
    for dir_path in dir_list:
        future = thread_pool.submit(stat_walk, args, dir_path, True, None, time.perf_counter())
        args.thread_future_set.add(future)
    while len(args.thread_future_set) > 0 or not args.thread_wait_queue.empty():
        while not args.thread_wait_queue.empty():
            if args.m_process_wait_queue.qsize() < args.max_process_queue_size:
                args.m_process_wait_queue.put(args.thread_wait_queue.get())
            elif len(args.thread_future_set) < args.max_thread_queue_size:
                future = thread_pool.submit(stat_walk, args, args.thread_wait_queue.get(), True, None,
                                            time.perf_counter())
                args.thread_future_set.add(future)
            else:
                break
        args.process_wait_queue_size = args.m_process_wait_queue.qsize()
        try:
            for future in futures.as_completed(args.thread_future_set, timeout=1):
                thread_dir_stat_map = future.result()
                add_dir_stat_map(args, process_dir_stat_map, thread_dir_stat_map)
                args.thread_future_set.remove(future)
        except concurrent.futures.TimeoutError:
            pass
        except Exception as e:
            print(f"threads error processing directory: {e}")
            args.thread_future_set.remove(future)
    return process_dir_stat_map


def stat_walk(args, top, need_output, thread_local_output_lines, start_time):
    local_dir_stat_map = DirectoryStatMap()
    # Each thread maintains its own output list
    if thread_local_output_lines is None:
        thread_local_output_lines = []
    try:
        try:
            scandir_it = os.scandir(top)
        except OSError as error:
            add_skip_to_dir_stat_map(args, local_dir_stat_map, error, top)
            return local_dir_stat_map

        with scandir_it:
            while True:
                try:
                    try:
                        entry = next(scandir_it)
                    except StopIteration:
                        break
                except OSError as error:
                    add_skip_to_dir_stat_map(args, local_dir_stat_map, error, top)
                    break

                try:
                    is_dir = entry.is_dir()
                except OSError:
                    is_dir = False

                path = os.path.join(top, entry.name)
                if is_dir:
                    if entry.name in args.exclude_dir_set:
                        continue
                    if not path.endswith('/'):
                        path += '/'
                    if path in args.exclude_full_path_dir_set:
                        continue
                    my_stat(args, local_dir_stat_map, thread_local_output_lines, path)
                    if entry.is_symlink():
                        continue
                    if time.perf_counter() - start_time > 1 and args.thread_wait_queue.qsize() < args.max_thread_queue_size - len(
                            args.thread_future_set) + args.max_process_queue_size - args.process_wait_queue_size:
                        args.thread_wait_queue.put(path)
                    else:
                        _local_dir_stat_map = stat_walk(args, path, False, thread_local_output_lines, start_time)
                        add_dir_stat_map(args, local_dir_stat_map, _local_dir_stat_map)
                else:
                    my_stat(args, local_dir_stat_map, thread_local_output_lines, path)
        if need_output and args.stat_type == INODE_LIST:
            output_stat_lines(args, local_dir_stat_map, thread_local_output_lines)
        return local_dir_stat_map
    except Exception as error:
        add_skip_to_dir_stat_map(args, local_dir_stat_map, error, top)
        return local_dir_stat_map


def output_stat_lines(args, local_dir_stat_map, thread_local_output_lines):
    with args.thread_lock:
        with args.m_output_file_lock:
            for output_path in args.output_path_list:
                with open(output_path, 'a') as output_handle:
                    output_handle.writelines(thread_local_output_lines)
    local_dir_stat_map.add_inode_num(len(thread_local_output_lines))
    thread_local_output_lines.clear()


def my_stat(args, local_dir_stat_map, thread_local_output_lines, item_path):
    try:
        _stat = os.lstat(item_path)
        if not args.need_filter or filter_inode(args, _stat):
            if args.stat_type == DIR_TREE:
                add_inode_to_dir_stat_map(args, local_dir_stat_map, item_path, _stat)
                # Record directory information
                if stat.S_ISDIR(_stat.st_mode) and get_depth_from_str(item_path) <= args.min_key_depth + args.depth:
                    local_dir_stat_map.get_or_create(item_path, args, _stat)
            elif args.stat_type == INODE_LIST:
                if filter_inode(args, _stat):
                    inode_stat_print(args, local_dir_stat_map, item_path, _stat, thread_local_output_lines)
        if args.use_all_inode_num or args.use_all_size:
            if args.stat_type == DIR_TREE:
                add_inode_to_dir_stat_map(args, local_dir_stat_map, item_path, _stat, all_mode=True)
                # Record directory information
                if stat.S_ISDIR(_stat.st_mode) and get_depth_from_str(item_path) <= args.min_key_depth + args.depth:
                    local_dir_stat_map.get_or_create(item_path, args, _stat)
    except Exception as error:
        add_skip_to_dir_stat_map(args, local_dir_stat_map, error, item_path)


def roll_output_file(args):
    for output_path in args.output_path_list:
        need_roll = os.path.isfile(output_path)
        if args.backup_count > 0 and need_roll:
            file_handler = RotatingFileHandler(output_path, backupCount=args.backup_count)
            file_handler.doRollover()


def validate_input_dirs(args):
    directories = []
    if args.input_from_file:
        with open(args.input, 'r') as file:
            for line in file:
                line = line.strip()
                if line:
                    directories.append(line)
    else:
        directories.extend([_dir.strip() for _dir in args.input.split(",")])
    # Check if each directory exists
    for index, directory in enumerate(directories):
        if not directory.endswith('/'):
            directory += '/'
            directories[index] = directory
        if not os.path.isdir(directory):
            raise argparse.ArgumentTypeError(f"Directory '{directory}' does not exist.")
    return directories


def check_and_init_args(args):
    args.output_path_list = args.output_path.split(",")
    args.min_key_depth = None
    if args.stat_type == DIR_TREE or args.stat_type == INODE_LIST:
        args.input_dirs = validate_input_dirs(args)
        for _dir in args.input_dirs:
            if args.min_key_depth is None:
                args.min_key_depth = get_depth_from_str(_dir)
            else:
                args.min_key_depth = min(args.min_key_depth, get_depth_from_str(_dir))
    args.exclude_dir_set = frozenset()
    if args.exclude_dirs is not None:
        args.exclude_dir_set = frozenset(args.exclude_dirs.split(","))
    args.exclude_full_path_dir_set = frozenset()
    if args.exclude_full_path_dirs is not None:
        exclude_full_path_dir_list = []
        for path in args.exclude_full_path_dirs.split(","):
            if not path.endswith('/'):
                path += '/'
            exclude_full_path_dir_list += [path]
        args.exclude_full_path_dir_set = frozenset(exclude_full_path_dir_list)

    args.max_process_queue_size = 100 * args.processes
    args.max_thread_queue_size = 100 * args.threads
    if args.output_format is None:
        if args.stat_type == DIR_TREE:
            args.output_format_list = ['path', 'inode_num', 'size', 'skip_num']
        elif args.stat_type == INODE_LIST:
            args.output_format_list = ['path', 'size']
    else:
        args.output_format_list = args.output_format.split(',')
    args.use_atime = "atime" in args.output_format_list or "atime_ms" in args.output_format_list
    args.use_mtime = "mtime" in args.output_format_list or "mtime_ms" in args.output_format_list
    args.use_ctime = "ctime" in args.output_format_list or "ctime_ms" in args.output_format_list
    args.use_inode = "inode" in args.output_format_list
    args.use_all_inode_num = "all_inode_num" in args.output_format_list
    args.use_all_size = "all_size" in args.output_format_list
    args.need_filter = (args.min_size is not None or args.max_size is not None
                        or args.atime is not None or args.atime_after is not None
                        or args.ctime is not None or args.ctime_after is not None
                        or args.mtime is not None or args.mtime_after is not None
                        or args.filter_inode_type is not None)


# / -> depth 0
# /a/ -> depth 1
# /a.txt -> depth 1
# /a/b/ -> depth 2
# /a/b.txt -> depth 2
def get_depth_from_str(file_path):
    if file_path.endswith('/'):
        return file_path.count('/') - 1
    return file_path.count('/')


def get_depth_from_list(file_path_list):
    if file_path_list[-1] == '':
        return len(file_path_list) - 2
    return len(file_path_list) - 1


def add_inode_to_dir_stat_map(args, input_dir_stat_map, inode_path, _stat, all_mode=False):
    inode_size = _stat.st_size if args.use_file_size else _stat.st_blocks
    base_depth = args.min_key_depth
    file_path_list = inode_path.split('/')
    file_depth = get_depth_from_list(file_path_list)
    dir_path = ''
    for i in range(0, min(1 + base_depth + args.depth, file_depth)):
        dir_path += file_path_list[i] + '/'
        if i >= base_depth:
            dir_stat = input_dir_stat_map.get_or_create(dir_path, args, _stat)
            if all_mode:
                dir_stat.add_all_inode_num(1)
                dir_stat.add_all_size(inode_size)
            else:
                dir_stat.add_item_count(1)
                dir_stat.add_item_size(inode_size)


def add_skip_to_dir_stat_map(args, input_dir_stat_map, error, inode_path):
    print("inode_path:{}, skip because error:{}".format(inode_path, error))
    file_path_list = inode_path.split('/')
    file_depth = get_depth_from_list(file_path_list)
    base_depth = args.min_key_depth
    if inode_path.endswith('/'):
        file_depth += 1
    dir_path = ''
    for i in range(0, min(1 + base_depth + args.depth, file_depth)):
        dir_path += file_path_list[i] + '/'
        if i >= base_depth:
            dir_stat = input_dir_stat_map.get_or_create(dir_path, args, None)
            dir_stat.add_skipped_item_count(1)


def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def stat_func(args):
    args.stat_finish = False
    dir_stat_map = DirectoryStatMap()
    args.start_time = time.time()
    with Manager() as manager:
        args.m_output_file_lock = manager.Lock()
        args.m_process_wait_queue = manager.Queue()
        args.add_wait_flag = False
        process_future_set = set()
        try:
            if args.print_process_time > 0:
                threading.Thread(target=stat_print_at_runtime, args=(args, dir_stat_map, sys.stdout, True)).start()
            if args.stat_type == DIR_TREE or args.stat_type == INODE_LIST:
                roll_output_file(args)
                init_file_header(args)
                with ProcessPoolExecutor(max_workers=args.processes) as walk_executor:
                    input_dir_chunks = list(chunks(args.input_dirs, args.max_thread_queue_size))
                    for input_dir_chunk in input_dir_chunks:
                        future = walk_executor.submit(stat_process, args, input_dir_chunk)
                        process_future_set.add(future)

                    while len(process_future_set) > 0 or not args.m_process_wait_queue.empty():
                        while not args.m_process_wait_queue.empty():
                            if args.max_process_queue_size <= len(process_future_set):
                                break
                            _dir = args.m_process_wait_queue.get()
                            future = walk_executor.submit(stat_process, args, [_dir])
                            process_future_set.add(future)
                        try:
                            for future in futures.as_completed(process_future_set, timeout=1):
                                local_dir_stat_map = future.result()
                                add_dir_stat_map(args, dir_stat_map, local_dir_stat_map)
                                process_future_set.remove(future)
                        except concurrent.futures.TimeoutError:
                            pass
                        except Exception as e:
                            print(f"Stat error processing directory: {e}")
                            process_future_set.remove(future)

                    args.stat_finish = True
                    if args.stat_type == DIR_TREE:
                        for output_path in args.output_path_list:
                            with open(output_path, 'a+') as output_file:
                                dir_stat_map_print(args, dir_stat_map, output_file)
                        dir_stat_map_print(args, dir_stat_map, sys.stdout, print_elapsed_time=True,
                                           clear_screen=(args.print_process_time > 0))
                    elif args.stat_type == INODE_LIST:
                        output_total_line_print(args, dir_stat_map, sys.stdout, print_elapsed_time=True,
                                                clear_screen=(args.print_process_time > 0))
        except Exception as e:
            print(f"Error in stat_func: {e}")
        args.stat_finish = True


def init_file_header(args):
    for output_path in args.output_path_list:
        file_exists = os.path.isfile(output_path)
        file_empty = not file_exists or os.path.getsize(output_path) == 0
        with open(output_path, 'a+') as output_file:
            with args.m_output_file_lock:
                if args.output_without_header:
                    continue
                if file_empty:
                    output_file.write(','.join(args.output_format_list) + '\n')
                    output_file.flush()


def main():
    parser = CustomArgumentParser(description='nas stat util args info')
    args = parser.parse_args()
    check_and_init_args(args)
    stat_func(args)


if __name__ == "__main__":
    main()
