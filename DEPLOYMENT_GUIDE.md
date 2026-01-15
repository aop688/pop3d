# Linux POP3服务器部署指南

## 🚨 重要安全警告

**当前代码仅适用于测试和学习，不推荐用于生产环境！**

## 版本说明

### 1. simple_pop3d (基础版本)
- **特点**: 最简化实现，仅支持基本POP3协议
- **适用**: 学习POP3协议、功能测试
- **风险**: 无安全防护，明文传输

### 2. secure_pop3d (改进版本) 
- **特点**: 添加了基础安全措施
- **适用**: 内部网络测试
- **安全改进**: 输入验证、连接限制、超时处理、日志记录

## 生产环境替代方案

### ✅ 推荐方案

1. **Dovecot** (强烈推荐)
   ```bash
   # Ubuntu/Debian
   sudo apt-get install dovecot-pop3d
   
   # CentOS/RHEL
   sudo yum install dovecot
   ```

2. **Courier-POP3**
   ```bash
   sudo apt-get install courier-pop3
   ```

3. **使用SSL隧道**
   ```bash
   # 用stunnel加密现有POP3服务
   sudo apt-get install stunnel4
   ```

## 如果必须使用当前代码

### 🔒 最小化安全措施

1. **仅限内部网络**
   ```bash
   # 防火墙限制
   sudo ufw allow from 192.168.0.0/16 to any port 110
   sudo ufw deny 110
   ```

2. **SSL加密隧道**
   ```bash
   # stunnel配置 (/etc/stunnel/pop3.conf)
   [pop3s]
   accept = 995
   connect = 127.0.0.1:110
   cert = /etc/ssl/certs/server.crt
   key = /etc/ssl/private/server.key
   ```

3. **监控配置**
   ```bash
   # 监控失败登录
   tail -f /var/log/auth.log | grep "SECURITY"
   ```

### 🚫 限制条件

- **用户数**: < 10个并发用户
- **网络**: 仅可信内网
- **数据**: 非敏感邮件
- **监控**: 持续安全审计

## 部署步骤

### 1. 编译
```bash
make clean && make
```

### 2. 测试运行
```bash
# 非特权端口测试
./secure_pop3d &

# 或特权端口（需要root）
sudo ./secure_pop3d
```

### 3. 客户端配置
```
服务器: localhost:110
用户名: aptuser
密码: pop3dabc123
加密: 无（仅测试）/ SSL隧道
```

### 4. 功能验证
```bash
# telnet测试
telnet localhost 110
USER aptuser
PASS pop3dabc123
STAT
QUIT
```

## 安全检查清单

- [ ] 仅在内部网络使用
- [ ] 配置SSL隧道
- [ ] 设置防火墙规则
- [ ] 启用日志监控
- [ ] 定期更新密码
- [ ] 监控异常活动
- [ ] 备份数据
- [ ] 安全审计

## 监控脚本示例

```bash
#!/bin/bash
# monitor_pop3d.sh
LOG_FILE="/var/log/pop3d_security.log"

# 检查失败登录
FAILED_LOGINS=$(grep "Authentication failure" /var/log/auth.log | wc -l)
if [ $FAILED_LOGINS -gt 10 ]; then
    echo "Warning: $FAILED_LOGINS failed login attempts" >> $LOG_FILE
fi

# 检查进程状态
if ! pgrep -f "secure_pop3d" > /dev/null; then
    echo "POP3 server is not running!" >> $LOG_FILE
fi
```

## 结论

对于**生产环境邮件服务器**，强烈建议使用：
- **Dovecot**: 成熟、安全、功能完整
- **Postfix + Dovecot**: 完整邮件解决方案

当前代码仅适合：
- 学习POP3协议
- 开发测试环境  
- 内部临时使用

**安全永远是第一优先级！**