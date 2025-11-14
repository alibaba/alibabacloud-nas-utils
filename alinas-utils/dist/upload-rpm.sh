FILEPATH=$1
AKID=$2
AKSEC=$3
SET_LATEST=0
LATEST_NAME="aliyun-alinas-utils-latest.al7.noarch.rpm"
SET_ECS_LATEST=0
ECS_LATEST_NAME="aliyun-alinas-utils-public.noarch.rpm"

REGIONS=("cn-beijing"  "cn-hangzhou"  "cn-zhangjiakou"  "cn-shanghai"  "cn-qingdao"  "cn-huhehaote"  "cn-wulanchabu" "cn-shenzhen" "cn-heyuan" "cn-guangzhou" "cn-chengdu" "cn-hongkong" "ap-southeast-1" "ap-southeast-2" "ap-northeast-2" "ap-southeast-3" "ap-southeast-5" "ap-northeast-1" "eu-central-1" "eu-west-1" "us-west-1" "us-east-1" "me-east-1" "ap-southeast-6" "ap-southeast-7" "ap-south-1")

help()
{
    echo 'Usage: sh upload-rpm $file_path $access_id $access_key [--set-latest] [--set-ecs-latest]'
    exit 1
}

if [ -z "$1" ]; then
    help
fi
if [ -z "$2" ]; then
    help
fi
if [ -z "$3" ]; then
    help
fi
if [[ $@ == *'--set-latest'* ]]; then
    SET_LATEST=1
fi
if [[ $@ == *'--set-ecs-latest'* ]]; then
    SET_ECS_LATEST=1
fi

FILENAME=`basename $FILEPATH`

get_md5()
{
    bucketname=$2
    FILENAME=$3
    endpoint=$4
    md5=`./ossutil stat oss://$bucketname/$FILENAME -e $endpoint --access-key-id=$AKID --access-key-secret=$AKSEC | grep Content-Md5`
    if [ $? -ne 0 ]; then
        echo "get md5 failed (file:$FILENAME bucket: $bucketname in region: $region)"
        eval "$1=''"
    fi
    md5=`echo $md5 | awk '{print $3}'`
    eval "$1=$md5"
}

check_md5()
{
    bucketname=$1
    FILENAME=$2
    endpoint=$3
    origin_md5=$4
    md5=''
    get_md5 md5 $bucketname $FILENAME $endpoint
    if [ "$md5" = "" ]; then
        echo "get md5 failed (file:$FILENAME bucket: $bucketname in region: $region)"
        return 1
    fi
    if [[ $origin_md5 != $md5 ]]; then
        echo "md5 not matched. (file:$FILENAME bucket: $bucketname in region: $region, origin:$origin_md5 md5:$md5)"
        return 1
    fi
    return 0
}

wait_bucket_sync()
{
    origin_md5=$1
    regions_check=("${REGIONS[@]}")
    while true; do
        echo 'Waiting all regions synced......'
        regions_not_ready=()
        for region in ${regions_check[*]}; do
            bucketname="aliyun-alinas-eac-${region}"
            endpoint="oss-${region}.aliyuncs.com"
            check_md5 $bucketname $FILENAME $endpoint $origin_md5
            local ret=$?
            if [ $ret -ne 0 ]; then
                regions_not_ready+=("$region")
                continue
            fi
            if [ $SET_LATEST -eq 1 ]; then
                check_md5 $bucketname $LATEST_NAME $endpoint $origin_md5
                local ret=$?
                if [ $ret -ne 0 ]; then
                    regions_not_ready+=("$region")
                fi
            fi
            if [ $SET_ECS_LATEST -eq 1 ]; then
                check_md5 $bucketname $ECS_LATEST_NAME $endpoint $origin_md5
                local ret=$?
                if [ $ret -ne 0 ]; then
                    regions_not_ready+=("$region")
                fi
            fi
        done
        if [ ${#regions_not_ready[@]} -eq 0 ]; then
            echo 'All regions synced, goodbye!'
            exit 0
        fi
        sleep 3
        echo ${regions_not_ready[@]}
        regions_check=("${regions_not_ready[@]}")
    done
}

wget https://gosspublic.alicdn.com/ossutil/1.7.13/ossutil64 -O ossutil
chmod a+x ossutil

upload_oss()
{
    local bucket=$1
    local endpoint=$2

    # backup latest
    curname=$(./ossutil read-symlink oss://$bucket/$LATEST_NAME -e $endpoint --access-key-id=$AKID --access-key-secret=$AKSEC | grep X-Oss-Symlink-Target | awk '{print $3}')
    ./ossutil cp oss://$bucket/$curname oss://$bucket/backup/$curname -e $endpoint --access-key-id=$AKID --access-key-secret=$AKSEC
    if [ $? -ne 0 ]; then
        echo "backup latest $curname failed $bucket"
        exit 1
    fi
    curname=$(./ossutil read-symlink oss://$bucket/$ECS_LATEST_NAME -e $endpoint --access-key-id=$AKID --access-key-secret=$AKSEC | grep X-Oss-Symlink-Target | awk '{print $3}')
    ./ossutil cp oss://$bucket/$curname oss://$bucket/backup/$curname -e $endpoint --access-key-id=$AKID --access-key-secret=$AKSEC
    if [ $? -ne 0 ]; then
        echo "backup ecs-latest $curname failed $bucket"
        exit 1
    fi

    ./ossutil cp $FILEPATH oss://$bucket/ -e $endpoint --access-key-id=$AKID --access-key-secret=$AKSEC
    if [ $? -ne 0 ]; then
        echo "upload $FILEPATH to bucket: $bucket failed"
        exit 1
    fi

    if [ $SET_LATEST -eq 1 ]; then
        ./ossutil create-symlink oss://$bucket/$LATEST_NAME oss://$bucket/$FILENAME -e $endpoint --access-key-id=$AKID --access-key-secret=$AKSEC
        if [ $? -ne 0 ]; then
            echo "create-symlink failed (bucket:$bucket file:$FILENAME link:$LATEST_NAME)"
            exit 1
        fi
    fi
    if [ $SET_ECS_LATEST -eq 1 ]; then
        ./ossutil create-symlink oss://$bucket/$ECS_LATEST_NAME oss://$bucket/$FILENAME -e $endpoint --access-key-id=$AKID --access-key-secret=$AKSEC
        if [ $? -ne 0 ]; then
            echo "create-symlink failed (bucket:$bucket file:$FILENAME link:$ECS_LATEST_NAME)"
            exit 1
        fi
    fi
}

upload_oss "aliyun-encryption" "oss-cn-beijing.aliyuncs.com"
upload_oss "aliyun-alinas-eac" "oss-cn-beijing.aliyuncs.com"
# bucket sync not supported in these regions
upload_oss "aliyun-alinas-eac-ap-northeast-2" "oss-ap-northeast-2.aliyuncs.com"
upload_oss "aliyun-alinas-eac-ap-southeast-7" "oss-ap-southeast-7.aliyuncs.com"

md5=''
get_md5 md5 "aliyun-alinas-eac" $FILENAME "oss-cn-beijing.aliyuncs.com"
if [ "$md5" = "" ]; then
    echo "get md5 failed (file:$FILENAME)"
    exit 1
fi

wait_bucket_sync $md5


