# NAS容量统计工具

## 依赖环境
- OS: Linux/macOS
- Python 3.6+

# 功能一：根据条件筛选出文件，并生成文件列表清单

入参列表：

|                                                                  | 参数                        | 示例                                                                                                                                                                                                                                                                                               |
|------------------------------------------------------------------|---------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 统计类型（必填）                                                         | \-t --type                | 功能一：过滤出inode列表功能，inode\_list<br>功能二：统计目录容量数，dir\_tree<br>（固定字符串表示类型）                                                                                                                                                                                                                             |
| 输入路径（必填）                                                         | \-i --input               | 多个则以逗号分隔<br>如：/cpfs/a/,/cpfs/b/                                                                                                                                                                                                                                                                  |
| 从文件中读取输入路径                                                       | \--input-from-file        | 开启后，将从--input所指的文件中获取输入目录，每行一个目录                                                                                                                                                                                                                                                                 |
| 输出文件地址                                                           | \-o --output-path         | /tmp/nas\_stat\_util.output<br>默认值为/tmp/nas\_stat\_util.output                                                                                                                                                                                                                                   |
| 人类阅读模式                                                           | \--human                  | 开启后所有输出将按人类易读模式考虑                                                                                                                                                                                                                                                                                |
| 允许保留的历史备份数                                                       | \--backup-count           | 默认值9<br>每次输出时，不会删除上次输出文件，而是重命名后留存一份历史，如<br>/tmp/nas\_stat\_util.output会重命名为/tmp/nas\_stat\_util.output.1<br>注意：设置为0时，不会替换上次的输出文件，而是会在文件末尾追加行                                                                                                                                                     |
| 并行进程数                                                            | \--processes              | 默认值10<br>仅建议调小此值，尤其是在3.6等低版本python中                                                                                                                                                                                                                                                              |
| 单进程的并发线程数                                                        | \--threads                | 默认值10<br>仅建议调小此值，尤其是在3.6等低版本python中                                                                                                                                                                                                                                                              |
| 打印过程间隔                                                           | \--print-process-time     | 单位为秒，默认0，不打印过程<br>非零时每(--print-process-time)秒打印当前统计信息                                                                                                                                                                                                                                            |
| 需要排除的文件夹名称                                                       | \--exclude-dirs           | 逗号分隔，如：.snapshot                                                                                                                                                                                                                                                                                 |
| 需要排除的文件夹全路径                                                      | \--exclude-full-path-dirs | 逗号分隔，如：/cpfs/${fsid}/.snapshots                                                                                                                                                                                                                                                                  |
| 决定输出文件格式                                                         | \--output-format          | 功能一默认值 <br>\--output-format path,size<br>可选值\[path,size,raw\_size,inode,atime,mtime,ctime,atime\_ms,mtime\_ms,ctime\_ms\]<br>功能二默认值<br>\--output-format path,inode\_num,size,skip\_num<br>可选值\[path,inode\_num,size,raw\_size,skip\_num,inode,atime,mtime,ctime,atime\_ms,mtime\_ms,ctime\_ms\]. |
| 决定统计时过滤的文件类型                                                     | \--filter-inode-type      | 默认值 all，默认记录所有inode<br>可选值：<br>\[all, regular\_file, dir\]                                                                                                                                                                                                                                       |
| 输出时不带行首（列名）                                                      | \--output-without-head    | 启用后，输出文件不带行首（列名）                                                                                                                                                                                                                                                                                 |
| 输出路径不带前缀                                                         | \--output-without-prefix  | 默认为空<br>配置后，输出的path，会将其中的(--output-without-prefix)替换为空串                                                                                                                                                                                                                                          |
| 文件大小下限（单位：字节Byte）                                                | \-s --min-size            | 50                                                                                                                                                                                                                                                                                               |
| 文件大小上限（单位：字节Byte）                                                | \--max-size               | 1000000000                                                                                                                                                                                                                                                                                       |
| 最近访问时间早于此值的文件<br>（整形时间戳，秒数，下同）                                   | \-a --atime               | 1735010275                                                                                                                                                                                                                                                                                       |
| 最近访问时间晚于此值的文件                                                    | \--atime-after            | 1735010275                                                                                                                                                                                                                                                                                       |
| 修改时间早于此值的文件                                                      | \-m --mtime               | 1735010275                                                                                                                                                                                                                                                                                       |
| 修改时间时间晚于此值的文件                                                    | \--mtime-after            | 1735010275                                                                                                                                                                                                                                                                                       |
| 变更时间早于此值的文件<br>ctime（Change Time）表示文件元数据（如权限、所有者等）或内容最后一次被更改的时间。 | \-c --ctime               | 1735010275                                                                                                                                                                                                                                                                                       |
| 变更时间晚于此值的文件                                                      | \--ctime-after            | 1735010275                                                                                                                                                                                                                                                                                       |

使用示例：
扫描/mnt/xxx/目录及其子目录，生成文件清单

```plaintext
python3 /tmp/nas_stat_util.py -t inode_list -i /mnt/xxx/
```

输出示例：

```plaintext
path,size,atime,mtime,ctime
/mnt/xxx/,0,1735112475,1735112259,1735112259
/mnt/xxx/y.txt,8192,1735116541,1735114382,1735114382
/mnt/xxx/yyy/,0,1735112737,1735112576,1735112576
```

# 功能二：查看指定目录及其子目录的大小

入参列表：

|                                                                  | 参数                        | 示例                                                                                                                                                                                                                                                                                               |
|------------------------------------------------------------------|---------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 统计类型（必填）                                                         | \-t --type                | 功能一：过滤出inode列表功能，inode\_list<br>功能二：统计目录容量数，dir\_tree<br>（固定字符串表示类型）                                                                                                                                                                                                                             |
| 输入路径（必填）                                                         | \-i --input               | 多个则以逗号分隔<br>如：/cpfs/a/,/cpfs/b/                                                                                                                                                                                                                                                                  |
| 从文件中读取输入路径                                                       | \--input-from-file        | 开启后，将从--input所指的文件中获取输入目录，每行一个目录                                                                                                                                                                                                                                                                 |
| 输出文件地址                                                           | \-o --output-path         | /tmp/nas\_stat\_util.output<br>默认值为/tmp/nas\_stat\_util.output                                                                                                                                                                                                                                   |
| 人类阅读模式                                                           | \--human                  | 开启后所有输出将按人类易读模式考虑                                                                                                                                                                                                                                                                                |
| 允许保留的历史备份数                                                       | \--backup-count           | 默认值9<br>每次输出时，不会删除上次输出文件，而是重命名后留存一份历史，如<br>/tmp/nas\_stat\_util.output会重命名为/tmp/nas\_stat\_util.output.1<br>注意：设置为0时，不会替换上次的输出文件，而是会在文件末尾追加行                                                                                                                                                     |
| 并行进程数                                                            | \--processes              | 默认值10<br>仅建议调小此值，尤其是在3.6等低版本python中                                                                                                                                                                                                                                                              |
| 单进程的并发线程数                                                        | \--threads                | 默认值10<br>仅建议调小此值，尤其是在3.6等低版本python中                                                                                                                                                                                                                                                              |
| 打印过程间隔                                                           | \--print-process-time     | 单位为秒，默认0，不打印过程<br>非零时每(--print-process-time)秒打印当前统计信息                                                                                                                                                                                                                                            |
| 需要排除的文件夹名称                                                       | \--exclude-dirs           | 逗号分隔，如：.snapshot                                                                                                                                                                                                                                                                                 |
| 需要排除的文件夹全路径                                                      | \--exclude-full-path-dirs | 逗号分隔，如：/cpfs/${fsid}/.snapshots                                                                                                                                                                                                                                                                  |
| 决定输出文件格式                                                         | \--output-format          | 功能一默认值 <br>\--output-format path,size<br>可选值\[path,size,raw\_size,inode,atime,mtime,ctime,atime\_ms,mtime\_ms,ctime\_ms\]<br>功能二默认值<br>\--output-format path,inode\_num,size,skip\_num<br>可选值\[path,inode\_num,size,raw\_size,skip\_num,inode,atime,mtime,ctime,atime\_ms,mtime\_ms,ctime\_ms\]. |
| 决定统计时过滤的文件类型                                                     | \--filter-inode-type      | 默认值 all，默认记录所有inode<br>可选值：<br>\[all, regular\_file, dir\]                                                                                                                                                                                                                                       |
| 输出时不带行首（列名）                                                      | \--output-without-head    | 启用后，输出文件不带行首（列名）                                                                                                                                                                                                                                                                                 |
| 输出路径不带前缀                                                         | \--output-without-prefix  | 默认为空<br>配置后，输出的path，会将其中的(--output-without-prefix)替换为空串                                                                                                                                                                                                                                          |
| 文件大小下限（单位：字节Byte）                                                | \-s --min-size            | 50                                                                                                                                                                                                                                                                                               |
| 文件大小上限（单位：字节Byte）                                                | \--max-size               | 1000000000                                                                                                                                                                                                                                                                                       |
| 最近访问时间早于此值的文件<br>（整形时间戳，秒数，下同）                                   | \-a --atime               | 1735010275                                                                                                                                                                                                                                                                                       |
| 最近访问时间晚于此值的文件                                                    | \--atime-after            | 1735010275                                                                                                                                                                                                                                                                                       |
| 修改时间早于此值的文件                                                      | \-m --mtime               | 1735010275                                                                                                                                                                                                                                                                                       |
| 修改时间时间晚于此值的文件                                                    | \--mtime-after            | 1735010275                                                                                                                                                                                                                                                                                       |
| 变更时间早于此值的文件<br>ctime（Change Time）表示文件元数据（如权限、所有者等）或内容最后一次被更改的时间。 | \-c --ctime               | 1735010275                                                                                                                                                                                                                                                                                       |
| 变更时间晚于此值的文件                                                      | \--ctime-after            | 1735010275                                                                                                                                                                                                                                                                                       |

dir_tree下额外入参

|          | 参数          | 示例                        |
|----------|-------------|---------------------------|
| 展示几层目录深度 | \-d --depth | 默认值2<br>0代表只展示输入dir自身下的信息 |

使用示例：

```plaintext
python3 /tmp/nas_stat_util.py -t dir_tree -i /mnt/xxx/ -d 1
```

输出示例：

```plaintext
path,inode_num,size,skip_num
/mnt/xxx/,121064,479956992,0
/mnt/xxx/aaa/,24214,96018432,0
/mnt/xxx/bbb/,24210,95969280,0
/mnt/xxx/ccc/,24210,95969280,0
/mnt/xxx/ddd/,24210,95969280,0
/mnt/xxx/eee/,24214,96018432,0
```

# 注意事项：

- 扫描过程涉及大量元数据读请求，可能会打满网络，建议在业务低峰的时候执行，或调小并行数。
- 指定的输入目录中不允许存在逗号，将多目录作为输入时，不允许目录间嵌套
