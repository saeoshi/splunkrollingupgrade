# splunkrollingupgrade

## Prepare
実行するノードから、rootでノンパスsshログインできるようにしておくこと

## Execute
python shc_upgrade_rpm.py -u https://XXX.XXX.XXX.XXX:8089 -d /opt/splunk -t 180 -n /home/ec2-user/splunk-7.1.3-51d9cac7b837-linux-2.6-x86_64.rpm -r root -s 7.1.3 --auth admin:XXXXXX

