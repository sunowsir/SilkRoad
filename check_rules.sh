#!/bin/bash
#
# File     : check_rules.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-01-26 17:40:10
#

nft -a list chain inet fw4 dstnat
nft -a list table inet bpf_accel
conntrack -L | grep 'OFFLOAD'
