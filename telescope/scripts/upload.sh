#!/bin/bash

# dir_gotrace containing .pcap files
dir_gotrace="/var/spool/gotrace"
dir_thorny="/var/spool/thorny"
dir_zeek="/var/spool/zeek"
bucket=$(cat /root/config/bucket.txt)
provider=$(cat /root/config/provider.txt)
region=$(cat /root/config/region.txt)
ip=$(cat /root/config/ip4.txt | sed -r 's/\./-/g' )


# Check if the dir_gotrace exists
if [ ! -d "$dir_gotrace" ]; then
    echo "dir_gotrace not found: $dir_gotrace"
else
    # Do we need to rewrite the pcaps?
    providers=("aws" "gcp" "azure" "terraform" "tencent")

    # Check if the file content matches any of the strings in the array
    for prov in "${providers[@]}"; do
        if [[ "$provider" == "$prov" ]]; then
            # Check if the dir_gotrace is not empty
            if [ "$(ls -A "$dir_gotrace")" ]; then
                /var/scripts/rewrite.sh
            fi
            break
        fi
    done


    cd $dir_gotrace
    for file in *.pcap.gz; do
        timestamp=$(echo "$file" | cut -d '.' -f 1 | cut -d '-' -f 2)
        year=$(date -u -d @"$timestamp" +"%Y")
        month=$(date -u -d @"$timestamp" +"%m")
        day=$(date -u -d @"$timestamp" +"%d")
        hour=$(date -u -d @"$timestamp" +"%H")

        target="tupload/${bucket}/provider=${provider}/region=${region}/ip=${ip}/year=${year}/month=${month}/day=${day}/hour=${hour}"

        if mc cp "${file}" "$target/"; then
            rm "$file" 
        fi
    done
fi



# thorny 

if [ ! -d "$dir_thorny" ]; then
    echo "dir_thorny not found: $dir_thorny"
else
    cd $dir_thorny
    for file in *.jsonl; do
        target="tupload/${bucket}/provider=${provider}/region=${region}/ip=${ip}"

        mc cp "${file}" "$target/"
    done
fi



# zeek

if [ ! -d "$dir_zeek" ]; then
    echo "dir_zeek not found: $dir_zeek"

else
    cd $dir_zeek
    for file in *.log; do
        target="tupload/${bucket}/provider=${provider}/region=${region}/ip=${ip}"

        mc cp "${file}" "$target/"
    done
fi

