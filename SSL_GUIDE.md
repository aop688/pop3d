# SSL POP3服务器 - 安全增强版

## 🚨 重要安全警告

**这是增强版本但仍不建议用于生产环境！生产环境请使用Dovecot。**

## 🔒 新增SSL功能

### 1. SSL/TLS加密
- **STARTTLS支持**: 端口1110，支持升级到TLS
- **直接SSL连接**: 端口1995，直接POP3S连接
- **现代加密**: 支持TLS 1.2+，禁用不安全协议

### 2. 证书管理
- **自动证书生成**: `-g` 参数生成自签名证书
- **自定义证书**: `-c` 和 `-k` 参数指定证书路径
- **证书验证**: 支持标准X.509证书

### 3. 安全增强
- **输入验证**: 严格的命令和参数验证
- **连接限制**: 防止资源耗尽攻击
- **IP过滤**: 仅允许内网连接
- **登录保护**: 限制失败登录次数
- **超时处理**: 自动断开空闲连接

## 📦 编译和安装

### 编译所有版本
```bash
make clean && make
```

### 生成测试证书
```bash
mkdir -p certs
./ssl_pop3d -g -c certs/server.crt -k certs/server.key
```

### 安装到系统
```bash
sudo make install
```

## 🚀 使用方法

### 基本使用
```bash
# 使用自签名证书测试
./ssl_pop3d -c certs/server.crt -k certs/server.key

# 使用生产证书
sudo ./ssl_pop3d -c /etc/ssl/certs/mail.crt -k /etc/ssl/private/mail.key
```

### 命令行参数
```bash
./ssl_pop3d [选项]
  -p 0|1     允许明文连接 (默认: 1)
  -c 文件     证书文件路径
  -k 文件     私钥文件路径  
  -g          生成自签名证书
```

## 🔧 客户端配置

### POP3S (直接SSL)
- **服务器**: localhost:1995
- **加密**: SSL/TLS
- **用户名**: aptuser
- **密码**: pop3dabc123

### POP3 + STARTTLS
- **服务器**: localhost:1110
- **加密**: STARTTLS
- **用户名**: aptuser
- **密码**: pop3dabc123

### 测试命令
```bash
# 测试直接SSL连接
openssl s_client -connect localhost:1995 -quiet

# 测试STARTTLS连接
openssl s_client -connect localhost:1110 -starttls pop3 -quiet
```

## 🛡️ 生产环境建议

### 1. 使用标准端口
修改 `ssl_pop3d.c` 中的端口定义：
```c
#define POP3_PORT 110   // 标准POP3端口
#define POP3S_PORT 995  // 标准POP3S端口
```

### 2. 使用正式证书
```bash
# 生成正式证书
sudo openssl req -x509 -newkey rsa:4096 -keyout /etc/ssl/private/mail.key \
  -out /etc/ssl/certs/mail.crt -days 365 -nodes \
  -subj "/C=CN/ST=State/L=City/O=Company/OU=Mail/CN=mail.example.com"

# 设置权限
sudo chmod 600 /etc/ssl/private/mail.key
sudo chmod 644 /etc/ssl/certs/mail.crt
```

### 3. 防火墙配置
```bash
# 只允许SSL连接
sudo ufw deny 110/tcp    # 禁用明文POP3
sudo ufw allow 995/tcp    # 允许POP3S

# 或允许带STARTTLS的POP3
sudo ufw allow 110/tcp    # 允许POP3 + STARTTLS
sudo ufw allow 995/tcp    # 允许POP3S
```

### 4. 系统服务配置
创建 `/etc/systemd/system/ssl-pop3d.service`:
```ini
[Unit]
Description=SSL POP3 Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ssl_pop3d -c /etc/ssl/certs/mail.crt -k /etc/ssl/private/mail.key
Restart=always
RestartSec=5
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
```

启用服务：
```bash
sudo systemctl enable ssl-pop3d
sudo systemctl start ssl-pop3d
sudo systemctl status ssl-pop3d
```

## 📊 监控和日志

### 查看实时日志
```bash
# 系统日志
sudo tail -f /var/log/syslog | grep pop3d

# 安全日志
sudo tail -f /var/log/auth.log | grep SECURITY
```

### 监控脚本
创建 `/usr/local/bin/monitor_pop3d.sh`:
```bash
#!/bin/bash
FAILED=$(grep -c "Authentication failure" /var/log/auth.log)
CONNECTIONS=$(netstat -an | grep :1995 | grep ESTABLISHED | wc -l)

if [ $FAILED -gt 10 ]; then
    echo "⚠️  警告: 检测到 $FAILED 次失败登录"
fi

if [ $CONNECTIONS -gt 20 ]; then
    echo "⚠️  警告: 当前活跃连接数 $CONNECTION"
fi

echo "SSL POP3服务器状态正常"
echo "失败登录: $FAILED, 活跃连接: $CONNECTIONS"
```

## 🔍 故障排除

### 证书问题
```bash
# 验证证书
openssl x509 -in certs/server.crt -text -noout

# 测试证书和私钥匹配
openssl x509 -noout -modulus -in certs/server.crt | openssl md5
openssl rsa -noout -modulus -in certs/server.key | openssl md5
```

### SSL连接测试
```bash
# 详细SSL测试
openssl s_client -connect localhost:1995 -showcerts -CAfile certs/server.crt

# 测试STARTTLS
openssl s_client -connect localhost:1110 -starttls pop3 -debug
```

### 常见错误
1. **证书权限错误**: 确保私钥文件权限为600
2. **端口被占用**: 检查端口是否被其他服务占用
3. **防火墙阻止**: 确保防火墙允许相关端口

## 📈 性能优化

### SSL优化参数
在代码中添加SSL上下文优化：
```c
SSL_CTX_set_cipher_list(ssl_ctx, "HIGH:!aNULL:!MD5");
SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_SERVER);
SSL_CTX_set_timeout(ssl_ctx, 300);
```

### 系统参数优化
```bash
# 增加文件描述符限制
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# 优化网络参数
echo "net.core.somaxconn = 1024" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 1024" >> /etc/sysctl.conf
```

## ⚖️ 生产环境对比

| 功能 | ssl_pop3d | Dovecot |
|------|-----------|---------|
| SSL/TLS | ✅ 基础支持 | ✅ 完整支持 |
| 认证 | 固定用户 | 多种后端 |
| 邮件存储 | 模拟 | 完整支持 |
| 安全审计 | 基础日志 | 详细审计 |
| 性能 | 基础 | 高性能 |
| 维护 | 需要定制 | 成熟稳定 |

## 🎯 结论

SSL版本显著增强了安全性，但仍存在以下限制：
- 固定认证信息
- 简单的邮件存储模拟
- 缺少高级安全功能

**生产环境强烈推荐使用Dovecot！**