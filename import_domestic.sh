#!/bin/bash
#
# File     : import_domestic.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-01-29 14:27:19
#

set -euo pipefail

# --- 配置 ---
RULE_FILE="/etc/openclash/rule_provider/Domestic"
MAP_PATH="/sys/fs/bpf/dns_steer/domestic_domains"
BATCH_FILE="/tmp/dns_batch.txt"

if [ ! -f "$RULE_FILE" ]; then
   echo "错误: 找不到文件 $RULE_FILE"
   exit 1
fi

echo "正在解析 $RULE_FILE 并构造精确的 LPM Key..."

# 清空批处理文件
rm -f "$BATCH_FILE"

# 使用 Python 进行符合内核逻辑的编码转换
python3 - <<EOF >> "$BATCH_FILE"
import struct
import sys

rule_file = "$RULE_FILE"
map_path = "$MAP_PATH"

def encode_dns_reversed_key(domain):
   # 1. 模拟 DNS 编码: baidu.com -> \x05baidu\x03com
   parts = domain.lower().strip('.').split('.')
   dns_encoded = b''
   for part in parts:
       if not part: continue
       # Label 长度字节 + Label 内容
       dns_encoded += struct.pack('B', len(part)) + part.encode()

   if not dns_encoded:
       return None

   # 2. 字节流整体翻转: \x05baidu\x03com -> moc\x03udiab\x05
   rev_data = dns_encoded[::-1]

   # --- 核心修正点 ---
   # length 必须是 dns_encoded 的原始长度 (baidu.com 为 10)
   length = len(rev_data)

   # prefixlen = (实际域名长度字节) * 8
   # 这样 LPM 匹配时，比对完域名最后一个字节就会判定命中，而不会去比对后面的 \0
   prefix_bits = (length) * 8

   # 3. 构造 HEX 字符串
   prefix_hex = " ".join(f"{b:02x}" for b in struct.pack('<I', prefix_bits))

   # domain 数组固定为 64 字节，后面用 0 填充，但 prefix_bits 保证了后面这些 0 不参与匹配比对
   padded = rev_data.ljust(64, b'\x00')
   domain_hex = " ".join(f"{b:02x}" for b in padded)

   return f"{prefix_hex} {domain_hex}"

try:
   with open(rule_file, 'r', encoding='utf-8') as f:
       for line in f:
           line = line.strip()
           if not line or line.startswith('#'):
               continue
            
           # 兼容 Clash 规则: DOMAIN-SUFFIX,baidu.com 或直接域名
           parts = line.split(',')
           domain = parts[-1].strip()
            
           # 简单校验域名合法性
           if '.' not in domain:
               continue

           hex_str = encode_dns_reversed_key(domain)
           if hex_str:
               print(f"map update pinned {map_path} key hex {hex_str} value hex 01 00 00 00")
except Exception as e:
   sys.stderr.write(f"处理出错: {str(e)}\n")
EOF

# 执行注入
if [ -s "$BATCH_FILE" ]; then
   count=$(wc -l < "$BATCH_FILE")
   echo "正在注入 $count 条规则到 eBPF Map..."
   bpftool batch file "$BATCH_FILE"
   echo "导入成功！"
   # rm -f "$BATCH_FILE" # 调试时可查看此文件
else
   echo "未解析到有效域名规则。"
fi
