#!/bin/bash

echo "=== SSL POP3服务器测试指南 ==="
echo

# 检查证书文件
if [ -f "certs/server.crt" ] && [ -f "certs/server.key" ]; then
    echo "✓ SSL证书文件已找到"
    echo "  证书: certs/server.crt"
    echo "  私钥: certs/server.key"
else
    echo "✗ SSL证书文件未找到，请先生成证书："
    echo "  ./ssl_pop3d -g -c certs/server.crt -k certs/server.key"
    exit 1
fi

echo
echo "启动SSL POP3服务器："
echo "1. 启动服务器："
echo "   ./ssl_pop3d -c certs/server.crt -k certs/server.key"
echo
echo "2. 服务器将监听："
echo "   - 端口 1110 (POP3 + STARTTLS)"
echo "   - 端口 1995 (直接SSL连接 - POP3S)"
echo
echo "3. 测试连接："
echo

echo "=== 测试1: STARTTLS连接 ==="
echo "telnet localhost 1110"
echo "然后输入："
echo "CAPA"
echo "STLS"
echo "(服务器将开始TLS握手)"
echo

echo "=== 测试2: 直接SSL连接 ==="
echo "openssl s_client -connect localhost:1995 -quiet"
echo
echo "然后输入："
echo "USER aptuser"
echo "PASS pop3dabc123"
echo "STAT"
echo "QUIT"
echo

echo "=== 测试3: 使用邮件客户端 ==="
echo "配置信息："
echo "服务器: localhost"
echo "端口: 1110 (STARTTLS) 或 1995 (SSL/TLS)"
echo "用户名: aptuser"
echo "密码: pop3dabc123"
echo "加密: STARTTLS 或 SSL/TLS"
echo

echo "=== 安全功能 ==="
echo "✓ SSL/TLS加密"
echo "✓ STARTTLS支持"
echo "✓ 证书验证"
echo "✓ 输入验证"
echo "✓ 连接限制"
echo "✓ 超时处理"
echo "✓ IP过滤"
echo "✓ 登录尝试限制"
echo "✓ 活动日志"
echo

echo "=== 生产环境部署 ==="
echo "1. 使用标准端口 (需要root权限):"
echo "   - 修改 ssl_pop3d.c 中的端口为 110 和 995"
echo "   - sudo ./ssl_pop3d -c /etc/ssl/certs/server.crt -k /etc/ssl/private/server.key"
echo
echo "2. 使用正式证书："
echo "   - 从CA获取证书，或使用Let's Encrypt"
echo "   - 将证书和私钥放在安全位置"
echo "   - 设置适当的文件权限 (私钥 600)"
echo
echo "3. 防火墙配置："
echo "   sudo ufw allow 110/tcp  # POP3 (如果允许)"
echo "   sudo ufw allow 995/tcp  # POP3S"
echo "   sudo ufw deny 110/tcp   # 如果只允许SSL"
echo

echo "=== 监控和日志 ==="
echo "查看系统日志："
echo "tail -f /var/log/syslog | grep pop3d"
echo "tail -f /var/log/auth.log | grep SECURITY"
echo

echo "⚠️  重要提醒："
echo "- 此版本仍不建议用于生产环境"
echo "- 生产环境请使用Dovecot等成熟邮件服务器"
echo "- 当前代码适合学习和测试使用"