# Windows 11 原生 DoT 安装/卸载器

## 功能
- 以管理员身份运行的交互式安装器
- 输入 DoT 主机名与端口（默认 853）
- 解析 → 严格 TLS 预握手（SNI=主机名）→ 选用可用 IP
- 关闭 DoH/DDR，启用 DoT；删除旧映射后写入新映射
- 将所有活动物理网卡 IPv4 DNS 设为选定 IP（仅此一个）
- 可选：网络屏蔽 853 时自动安装并连接 Cloudflare WARP 再重试
- 卸载：恢复 DoH/DDR 默认、DNS 恢复为 DHCP（或按备份恢复）、可选卸载 WARP

## 使用
1. 下载 `dot_installer_cn.py` 到 Windows 11 机器。
2. **以管理员身份**运行 PowerShell：
   ```powershell
   python dot_installer.py
   ```
   按提示操作。

## 打包为 EXE
已写好 PyInstaller 打包脚本：
```bat
pyinstaller --onefile --uac-admin --name DoT-Installer dot_installer.py
```
生成的 `dist\DoT-Installer.exe` 可直接双击运行（自动请求管理员）。

> 提示：若系统未安装 PyInstaller，先执行：
> ```powershell
> pip install pyinstaller
> ```

## 回滚
在程序主菜单选择“卸载并恢复”，或运行安装器后选择卸载选项。备份文件位于：
- 备份：`%ProgramData%\DoT_Installer\backup.json`
- 日志：`%LOCALAPPDATA%\DoT_Installer\install_*.log`
