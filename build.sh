#!/bin/bash
#
# File     : build.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-01-21 14:24:02
#

# 1. 定义 SDK 路径
export BPF_SDK=/home/openwrt/llvm-bpf-21.1.6.Linux-x86_64/llvm-bpf

# 2. 定义 OpenWrt 平台头文件路径 (关键！)
# 注意：请根据你的实际 staging_dir 名字微调（x86_64_musl 还是其他）
export OPENWRT_STAGING=/home/openwrt/openwrt-25.12/staging_dir
export TARGET_INC=$OPENWRT_STAGING/target-x86_64_musl/usr/include
export TOOLCHAIN_INC=$OPENWRT_STAGING/toolchain-x86_64_gcc-14.3.0_musl/usr/include

# 3. 使用 SDK 中的 clang 编译
$BPF_SDK/bin/clang -O2 -target bpf -g \
    -I$BPF_SDK/include \
    -I$TARGET_INC \
    -I$TOOLCHAIN_INC \
    -c tc_direct_path.c -o tc_direct_path.o

