# DirectPath 加速引擎
> DirectPath加速引擎包括：
> 1. 直连流量加速引擎：利用ebpf实现国内IP流量快速转发
> 2. 直连DNS加速引擎：利用ebpf实现国内域名DNS请求不受openclash等软件的控制直达openwrt上部署的dns服务器
> :warning:请详细阅读代码，根据自身需求修改宏定义配置以及其他代码，请勿直接使用,后果自负

## 部署方法
  > 若执`check_cache.sh`发现缓存急速上涨并爆满，大概率是内网的P2P或PCDN服务导致

  1. 解压openwrt编译好的llvm工具链：`llvm-bpf-21.1.6.Linux-x86_64`
  2. 将代码`tc_direct_path.c`、`dns_steer.c`和编译脚本`build.sh`拷贝到工具链目录中`llvm-bpf-21.1.6.Linux-x86_64/llvm-bpf/`
  3. 执行编译脚本`build.sh` 
  4. 拷贝生成的`tc_direct_path.o`以及`dns_steer.o`到openwrt设备上 
  5. 拷贝其他脚本`cleanup_env.sh`、`deploy_direct_path.sh`以及`load_china_ip.sh`等到openwrt设备上与`tc_direct_path.o`同目录
  6. 部署执行`deploy_direct_path.sh`，然后载入国内域名执行`load_china_ip.sh`
  7. 部署执行dns直连脚本：`./manage_dns_bpf.sh stop && ./manage_dns_bpf.sh start && ./import_domestic.sh`

## 恢复环境

  1. 如需恢复环境执行`cleanup_env.sh`
  
## 调试信息 

  1. 查看调试信息，可将代码中的打印打开，然后在`openwrt`设备上执行：`cat /sys/kernel/debug/tracing/trace_pipe`
  2. 执行`monitor_hotpath.sh`脚本查看当前缓存存储的地址
  3. 执行`check_cache.sh`查看缓存利用率信息

## 缓存 

  1. 查看缓存利用率，执行 `check_cache.sh`
  2. 执行`monitor_hotpath.sh`脚本查看当前缓存存储的地址

## 计划/目标
  > 暂无单独包装为某个发行版软件包或者openwrt带界面的插件的计划

  1. 支持IPv6
  2. 解决openwrt部署直连DNS加速引擎后，下属设备无法向公网DNS发送请求的问题
