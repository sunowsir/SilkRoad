# SilkRoad
eBPF学习项目：利用ebpf实现国内IP绕过openclash实现快速转发

## 部署方法

  1. 解压openwrt编译好的llvm工具链：`llvm-bpf-21.1.6.Linux-x86_64`
  2. 将代码`tc_direct_accel.c`和编译脚本`build.sh`拷贝到工具链目录中`llvm-bpf-21.1.6.Linux-x86_64/llvm-bpf/`
  3. 执行编译脚本`build.sh` 
  4. 拷贝生成的`tc_direct_accel.o`到openwrt设备上 
  5. 拷贝其他脚本`cleanup_accel.sh`、`deploy_accel.sh`以及`load_china_ip.sh`到openwrt设备上与`tc_direct_accel.o`同目录
  6. 部署执行`deploy_accel.sh`，然后载入国内域名执行`load_china_ip.sh`
  7. 查看调试信息可在`openwrt`设备上执行：`cat /sys/kernel/debug/tracing/trace_pipe`
  8. 如需恢复环境执行`cleanup_accel.sh`
  
