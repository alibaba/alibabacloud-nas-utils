#!/bin/bash
function hr {
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
}
# 划线
hr
# 检查/etc/os-release文件是否存在
if [ -f /etc/os-release ]; then
    # 加载系统信息
    . /etc/os-release
    echo -e "\033[0;32m系统是：$NAME, 版本号：$VERSION\033[0m"
else
    echo -e "\033[0;31m找不到系统文件\033[0m"
    exit 1
fi
# 再划线
hr
hr
# 根据系统名称判断要检查的包
if [[ "$NAME" == "Ubuntu" ]]; then
    directory_path="/home"
    if ! ls ${directory_path}/aliyun-alinas-utils-*.deb 1> /dev/null 2>&1; then
        echo -e "\033[0;31m在目录 ${directory_path} 下没有找到相关的 deb 包\033[0m"
        exit 1
    fi
    # 安装deb包
    sudo dpkg -i ${directory_path}/aliyun-alinas-utils-*.deb
    sudo apt-get update
    echo | sudo apt --fix-broken install
    echo | sudo add-apt-repository universe
    echo | sudo add-apt-repository multiverse
    sudo apt-get install nfs-common stunnel4 haproxy -y  # 修复可能的依赖问题
    if [ $? -eq 0 ]; then
        echo -e "\033[0;32maliyun-alinas-utils 包安装成功\033[0m"
    else
        echo -e "\033[0;31m安装aliyun-alinas-utils失败了\033[0m"
        exit 1
    fi
    hr
elif [[ "$NAME" == "CentOS Linux" ]] || [[ "$NAME" == "Alibaba Cloud Linux" ]]; then
    directory_path="/home"
    if ! ls ${directory_path}/aliyun-alinas-utils-*.rpm 1> /dev/null 2>&1; then
        echo -e "\033[0;31m在目录 ${directory_path} 下没有找到相关的 rpm 包\033[0m"
        exit 1
    fi
    # 安装rpm包
    sudo yum install ${directory_path}/aliyun-alinas-utils-*.rpm -y
    if [ $? -eq 0 ]; then
        echo -e "\033[0;32maliyun-alinas-utils 包安装成功\033[0m"
    else
        echo -e "\033[0;31m安装aliyun-alinas-utils失败了\033[0m"
        exit 1
    fi
    hr
else
    echo -e "\033[0;31m目前脚本不支持CentOS，Alibaba，Ubuntu以外的系统\033[0m"
    exit 1
fi


hr
mount_cpfs_nfs_output=$(which mount.cpfs-nfs 2>&1)
# 判断命令是否执行成功
if [ $? -eq 0 ]; then
    echo -e "\033[0;32mcpfs-nfs命令执行成功，输出如下：\033[0m"
    echo -e "\033[0;32m$mount_cpfs_nfs_output\033[0m"
else
    echo -e "\033[0;31mcpfs-nfs命令执行失败，错误输出如下：\033[0m"
    echo -e "\033[0;31m$mount_cpfs_nfs_output\033[0m"
fi
hr

hr
read -p "输入你想创建cpfs挂载目录名： " filename
# 写死的路径
path="/mnt"
# 完整的目录路径
fullpath="$path/$filename"
# 检查目录是否已经存在
if [ -d "$fullpath" ]; then
    echo -e "\033[0;31mcpfs挂载目录已经存在了：$fullpath\033[0m"
else
    # 创建目录
    mkdir "$fullpath"
    if [ $? -eq 0 ]; then
        echo -e "\033[0;32mcpfs挂载目录创建成功：$fullpath\033[0m"
    else
        echo -e "\033[0;31mcpfs挂载目录创建失败了。\033[0m"
    fi
fi
hr

hr
read -p "输入cpfs挂载点： " file
sudo mount -t cpfs-nfs -o vers=3,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport "$file" "$fullpath"
if [ $? -eq 0 ]; then
    echo -e "\033[0;32mcpfs挂载成功\033[0m"
else
    echo -e "\033[0;31mcpfs挂载失败\033[0m"
    exit 1
fi
hr

hr
read -p "（查看内网ip地址）输入cpfs挂载点域名： " domin
# 使用grep命令提取对应行的内容
output=$(grep cpfs_primary /var/run/cpfs/haproxy-config."$domin")
# 使用grep工具提取IP地址
ip_address=$(echo "$output" | grep -oP '(\d{1,3}\.){3}\d{1,3}' | head -n 1)
if [ -n "$ip_address" ]; then
    echo -e "\033[0;32mCPFS挂载内网IP地址是：$ip_address\033[0m"
else
    echo -e "\033[0;31m没找到CPFS挂载内网IP地址。\033[0m"
    exit 1
fi
hr

hr
# cpfs的内网存在ip
command_output=$(host -t TXT "$domin")
# 使用grep提取所有IP地址并存入数组ips中
ips=($(echo "$command_output" | grep -oP '\b(\d{1,3}\.){3}\d{1,3}\b'))
# 检查是否有提取到IP
if [ ${#ips[@]} -eq 0 ]; then
    echo -e "\033[0;31m没有找到cpfs的内网IP组。\033[0m"
    exit 1
fi
# 从ips数组中随机选择一个IP
random_ip=${ips[$RANDOM % ${#ips[@]}]}

# 填写域名，例如: cpfs-XXXXX-XXXXXX.cn-shanghai.cpfs.aliyuncs.com
domain="$domin"
new_primary=$random_ip
if [ -z "$domain" ]; then
    echo "domain is empty"
    echo "domain: $domain"
elif ! grep -w $domain /proc/mounts; then
    echo "domain is not mounted on this client"
    echo "domain: $domain"
elif [ -z "$new_primary" ]; then
    echo "new_primary is empty"
    echo "new_primary: $new_primary"
else
  old_primary=$(grep 'cpfs_primary' /var/run/cpfs/haproxy-config.$domain|awk '{print $3}'|awk -F: '{print $1}')
  old_backup=$(grep 'cpfs_backup' /var/run/cpfs/haproxy-config.$domain|awk '{print $3}'|awk -F: '{print $1}')
  if [ "$new_primary" == "$old_primary" ]; then
     echo "new_ip[$new_primary] == old_ip[$old_primary], no need to change"
  else
     echo -e "随机更改cpfs内网ip"
     echo -e "\nruning the commond:"
     cmd="cpfsu switch_server manual --domain $domain --old_primary_server $old_primary --old_backup_server $old_backup --new_primary_server $new_primary --new_backup_server $old_primary"
     echo $cmd
     $cmd
  fi
fi
hr

hr
read -p "（再次查看内网ip地址）输入cpfs挂载点域名： " domin
# 使用grep命令提取对应行的内容
output=$(grep cpfs_primary /var/run/cpfs/haproxy-config."$domin")
# 使用grep工具提取IP地址
ip_address=$(echo "$output" | grep -oP '(\d{1,3}\.){3}\d{1,3}' | head -n 1)
if [ -n "$ip_address" ]; then
    echo -e "\033[0;32m(更改后的)CPFS挂载内网IP地址是：$ip_address\033[0m"
else
    echo -e "\033[0;31m没找到IP地址。\033[0m"
    exit 1
fi
hr

hr
sudo umount "$fullpath"
if [ $? -eq 0 ]; then
    echo -e "\033[0;32mcpfs卸载成功\033[0m"
else
    echo -e "\033[0;31mcpfs卸载失败\033[0m"
fi
hr