# -*- coding: utf-8 -*-
"""
交互式 Windows 11 原生 DoT 安装/卸载器
- 以管理员身份运行（自动检测）
- 用户输入 DoT 主机名和端口（默认 853）
- 解析主机名 -> 候选 IP（优先 IPv4）
- 对每个 IP 进行严格 TLS 预握手（SNI=主机名），选择可用 IP
- 关闭 DoH/DDR，启用 DoT；删除旧映射后写入新的加密映射
- 将所有活动物理网卡的 IPv4 DNS 设为 选定 IP（仅此一个）
- 可选：若 853 被封，支持安装 Cloudflare WARP 并连接再重试
- 卸载：恢复 DoH/DDR 默认、将网卡 DNS 恢复为 DHCP、删除映射；可选卸载 WARP
日志：%LOCALAPPDATA%\DoT_Installer\install_*.log
备份：%ProgramData%\DoT_Installer\backup.json （保存接口 DNS 原状）

注意：
- 本工具调用 Windows 自带 netsh / PowerShell，无第三方 Python 依赖。
- 仅支持 Windows 11（需要 'netsh dnsclient'）。
"""

from __future__ import annotations
import ctypes
import os
import re
import ssl
import socket
import subprocess
import sys
import time
import json
from datetime import datetime
from pathlib import Path

APP_DIR = Path(os.environ.get("LOCALAPPDATA", ".")) / "DoT_Installer"
APP_DIR.mkdir(parents=True, exist_ok=True)
LOG_PATH = APP_DIR / ("install_%s.log" % datetime.now().strftime("%Y%m%d_%H%M%S"))
BK_DIR = Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "DoT_Installer"
BK_DIR.mkdir(parents=True, exist_ok=True)
BK_FILE = BK_DIR / "backup.json"

def log(msg: str):
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def run(cmd: list[str] | str, check: bool=False, capture: bool=False) -> subprocess.CompletedProcess:
    if isinstance(cmd, str):
        shell=True
        cmd_to_show = cmd
    else:
        shell=False
        cmd_to_show = " ".join(cmd)
    log(f"[RUN] {cmd_to_show}")
    return subprocess.run(cmd, shell=shell, check=check, capture_output=capture, text=True, encoding="utf-8", errors="ignore")

def prompt_yes_no(question: str, default_yes=True) -> bool:
    prompt = " [Y/n] " if default_yes else " [y/N] "
    while True:
        ans = input(question + prompt).strip().lower()
        if not ans:
            return default_yes
        if ans in ("y", "yes", "是", "好", "确定"):
            return True
        if ans in ("n", "no", "否", "不"):
            return False
        print("请输入 y 或 n。")

def resolve_hostname(host: str, prefer_ipv4: bool=True) -> list[str]:
    # 使用 PowerShell 的 Resolve-DnsName，避免额外依赖
    ips = []
    servers = ["223.5.5.5","223.6.6.6","1.1.1.1","8.8.8.8"]
    types_seq = ["A","AAAA"] if prefer_ipv4 else ["AAAA","A"]
    for s in servers:
        for t in types_seq:
            try:
                ps = f"Resolve-DnsName {host} -Server {s} -Type {t} -DnsOnly -NoHostsFile"
                cp = run(["powershell","-NoProfile","-Command", ps], capture=True)
                out = cp.stdout or ""
                for m in re.finditer(r"(?m)^\s*{}".format(host.replace(".","[.]"))+r"\s+\w+\s+\d+\s+\w+\s+([\da-fA-F:.]+)", out):
                    ips.append(m.group(1))
                if ips:
                    return sorted(set(ips), key=lambda x: (":" in x, x))  # IPv4 优先
            except Exception:
                pass
    return sorted(set(ips), key=lambda x: (":" in x, x))

def tls_preflight(ip: str, sni: str, port: int=853, timeout: float=5.0) -> tuple[bool,str,str]:
    try:
        ctx = ssl.create_default_context()
        # 证书名校验：server_hostname=sni
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                cert = ssock.getpeercert()
                # 提取 CN
                subject = dict(x[0] for x in cert.get('subject', ()))
                cn = subject.get('commonName', '')
                not_after = cert.get('notAfter', '')
                return True, cn, not_after
    except Exception as e:
        log(f"[TLS] {ip}:{port} 预握手失败: {e}")
        return False, "", ""

def ensure_warp() -> bool:
    log("尝试静默安装并连接 Cloudflare WARP…")
    # 安装
    cp = run(["winget","install","--id=Cloudflare.Warp","-e","--silent","--accept-package-agreements","--accept-source-agreements"])
    # warp-cli.exe 路径
    cli = Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Cloudflare" / "Cloudflare WARP" / "warp-cli.exe"
    if not cli.exists():
        cli = Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Cloudflare" / "Cloudflare WARP" / "warp-cli.exe"
    if not cli.exists():
        log("未找到 warp-cli.exe，WARP 安装可能失败。")
        return False
    run([str(cli), "--accept-tos", "register"])
    run([str(cli), "set-mode", "warp"])
    run([str(cli), "connect"])
    # 等待连接
    deadline = time.time() + 120
    while time.time() < deadline:
        cp = run([str(cli), "status"], capture=True)
        if "Connected" in (cp.stdout or ""):
            log("WARP 已连接。")
            return True
        time.sleep(2)
    log("WARP 在超时时间内未连接成功。")
    return False

def backup_dns():
    """备份各网卡 DNS 设置到 BK_FILE"""
    data = {"ifaces": []}
    cp = run(["powershell","-NoProfile","-Command","Get-DnsClientServerAddress | ConvertTo-Json -Depth 4"], capture=True)
    if cp.stdout:
        try:
            arr = json.loads(cp.stdout)
            if isinstance(arr, dict):
                arr = [arr]
            for it in arr or []:
                data["ifaces"].append({
                    "InterfaceIndex": it.get("InterfaceIndex"),
                    "InterfaceAlias": it.get("InterfaceAlias"),
                    "AddressFamily": it.get("AddressFamily"),
                    "ServerAddresses": it.get("ServerAddresses"),
                })
        except Exception as e:
            log(f"备份解析失败: {e}")
    try:
        with open(BK_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        log(f"已备份 DNS 到 {BK_FILE}")
    except Exception as e:
        log(f"写入备份失败: {e}")

def restore_dns_from_backup():
    if not BK_FILE.exists():
        log("未找到备份文件，将改为重置为 DHCP。")
        reset_dns_to_dhcp()
        return
    try:
        data = json.loads(BK_FILE.read_text("utf-8"))
    except Exception as e:
        log(f"备份文件损坏：{e}；将改为重置为 DHCP。")
        reset_dns_to_dhcp()
        return
    # 逐接口恢复
    for it in data.get("ifaces", []):
        idx = it.get("InterfaceIndex")
        servers = it.get("ServerAddresses") or []
        if not idx:
            continue
        if not servers:
            run(["powershell","-NoProfile","-Command", f"Set-DnsClientServerAddress -InterfaceIndex {idx} -ResetServerAddresses"])
        else:
            # 只恢复 IPv4/IPv6 各自的地址集合
            addrs = " ".join(servers)
            run(["powershell","-NoProfile","-Command", f"Set-DnsClientServerAddress -InterfaceIndex {idx} -ServerAddresses {addrs}"])
    log("已根据备份恢复各接口 DNS。")

def reset_dns_to_dhcp():
    run(["powershell","-NoProfile","-Command",
         r"Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true } | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.IfIndex -ResetServerAddresses }"])

def disable_doh_dot_ddr(enable_dot: bool):
    if enable_dot:
        run(["netsh","dnsclient","set","global","doh=no","dot=yes","ddr=no"])
    else:
        run(["netsh","dnsclient","set","global","doh=auto","dot=no","ddr=yes"])
    # 接口级 DDR 也关掉/恢复
    if enable_dot:
        run(["powershell","-NoProfile","-Command",
             r"Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.HardwareInterface -eq $true} | ForEach-Object { netsh dnsclient set interface name=""$($_.Name)"" ddr=no ddrfallback=no }"])
    else:
        run(["powershell","-NoProfile","-Command",
             r"Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.HardwareInterface -eq $true} | ForEach-Object { netsh dnsclient set interface name=""$($_.Name)"" ddr=yes ddrfallback=yes }"])

def delete_mapping(server_ip: str):
    run(["netsh","dnsclient","delete","encryption",f"server={server_ip}","protocol=doh"])
    run(["netsh","dnsclient","delete","encryption",f"server={server_ip}","protocol=dot"])

def add_mapping(server_ip: str, dothost: str|None, udpfallback_no=True):
    args = ["netsh","dnsclient","add","encryption",f"server={server_ip}"]
    if dothost is None:
        # dothost=":" -> 仅加密不校验主机名
        args += [r"dothost=:"]
    else:
        args += [f"dothost={dothost}"]
    args += ["autoupgrade=yes", f"udpfallback={'no' if udpfallback_no else 'yes'}"]
    run(args)

def set_all_nics_dns(server_ip: str):
    run(["powershell","-NoProfile","-Command",
         r"$ifaces=Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true }; foreach($i in $ifaces){ Set-DnsClientServerAddress -InterfaceIndex $i.IfIndex -ServerAddresses " + server_ip + r" }"])

def flush_dns():
    run(["ipconfig","/flushdns"])

def show_status(server_ip: str):
    run(["netsh","dnsclient","show","global"])
    run(["netsh","dnsclient","show","encryption",f"server={server_ip}"])
    run(["netsh","dnsclient","show","state"])

def do_install():
    if not is_admin():
        print("请以【管理员身份】运行本程序。按任意键退出…")
        input()
        return

    print("=== Windows 11 原生 DoT 安装器===\n")
    print("说明：本工具将为你配置系统级 DNS-over-TLS。")
    print("提示：若网络屏蔽 853/TCP，可选择使用 Cloudflare WARP 穿透。")

    host = input("请输入 DoT 主机名（去掉lts://前缀）: ").strip()
    if not host:
        print("未输入主机名，已退出。"); return
    port_s = input("请输入端口（默认 853，回车使用默认）: ").strip()
    port = int(port_s) if port_s else 853

    try_warp = prompt_yes_no("如遇 853 被封，是否自动安装并连接 Cloudflare WARP 后再次尝试？", True)
    strict_only = prompt_yes_no("是否【只允许严格模式】（证书/主机名不匹配就终止，不使用仅加密模式）？", True)

    # 冲突检查：如果之前配置过同一 IP 映射，将覆盖
    log("开始备份当前 DNS 设置…")
    backup_dns()

    log(f"解析 {host} …")
    ips = resolve_hostname(host, prefer_ipv4=True)
    if not ips:
        print("无法解析主机名，已退出。")
        return
    print("候选 IP：", ", ".join(ips))

    # 严格预握手
    chosen_ip = None
    for ip in ips:
        ok, cn, exp = tls_preflight(ip, host, port)
        if ok:
            print(f"[严格握手成功] {ip}: CN={cn}, 到期={exp}")
            chosen_ip = ip; break
        else:
            print(f"[严格握手失败] {ip}:{port}")

    used_warp = False
    if not chosen_ip and try_warp:
        print("准备安装并连接 WARP 以尝试穿透 853…")
        if ensure_warp():
            used_warp = True
            # 再试严格握手
            for ip in ips:
                ok, cn, exp = tls_preflight(ip, host, port)
                if ok:
                    print(f"[严格握手成功] {ip}: CN={cn}, 到期={exp}")
                    chosen_ip = ip; break
                else:
                    print(f"[严格握手失败] {ip}:{port}")
        else:
            print("WARP 未能连接；将继续后续流程。")

    crypto_only = False
    if not chosen_ip:
        if strict_only:
            print("所有 IP 的严格握手均失败，且你选择了仅严格模式。已退出。")
            return
        print("进入【仅加密模式】（不校验证书主机名）。")
        # 选首个能连通 853 的 IP
        for ip in ips:
            try:
                with socket.create_connection((ip, port), timeout=3.0) as s:
                    chosen_ip = ip; break
            except Exception:
                pass
        if not chosen_ip:
            print("未发现可连通 853/TCP 的 IP。请检查网络或手动开启 WARP/VPN 后重试。")
            return
        crypto_only = True

    print(f"选定服务器 IP：{chosen_ip}")
    print("开始写入系统配置（将覆盖旧有同 IP 的 DoT/DoH 映射）…")

    # 打开 DoT，关闭 DoH/DDR；接口也关闭 DDR
    disable_doh_dot_ddr(enable_dot=True)
    # 删除旧映射
    delete_mapping(chosen_ip)
    # 写入新映射
    if crypto_only:
        add_mapping(chosen_ip, None, udpfallback_no=True)   # dothost=":"
    else:
        add_mapping(chosen_ip, host, udpfallback_no=True)
    # 设置网卡 DNS
    set_all_nics_dns(chosen_ip)
    # 刷新 & 显示
    flush_dns()
    show_status(chosen_ip)

    # 功能测试
    print("做一次解析测试：example.com …")
    run(["powershell","-NoProfile","-Command", f"Resolve-DnsName example.com -Server {chosen_ip} -Type A -NoHostsFile -DnsOnly"])

    print("\n完成。日志路径：", LOG_PATH)
    if used_warp:
        print("（提示：你已启用 WARP，如不再需要可在卸载流程选择卸载它。）")

def do_uninstall():
    if not is_admin():
        print("请以【管理员身份】运行本程序。按任意键退出…")
        input()
        return
    print("=== 卸载/恢复 ===")
    # 关 DoT / 恢复 DoH/DDR
    disable_doh_dot_ddr(enable_dot=False)
    # 恢复网卡 DNS（按备份）或重置为 DHCP
    if BK_FILE.exists() and prompt_yes_no("检测到之前的 DNS 备份，是否按备份恢复？", True):
        restore_dns_from_backup()
    else:
        reset_dns_to_dhcp()
        print("已将所有活动物理网卡 DNS 恢复为 DHCP。")
    # 尝试删除我们可能写入的映射（无法精确枚举，只处理常见情况）
    # 从备份中猜测，或者提示用户输入上次的 IP：
    ip_guess = input("如需清理加密映射，请输入要删除映射的服务器 IP（回车跳过）: ").strip()
    if ip_guess:
        delete_mapping(ip_guess)
        print(f"已请求删除 {ip_guess} 的 DoT/DoH 映射。")
    # 可选卸载 WARP
    if prompt_yes_no("是否卸载 Cloudflare WARP（若之前安装过）？", False):
        run(["winget","uninstall","--id=Cloudflare.Warp","-e"])
    flush_dns()
    print("已完成卸载/恢复。")

def main():
    if not is_admin():
        print("** 请右键以【管理员身份】运行本程序，否则无法生效。**")
        input("按任意键退出…")
        return
    print("===============================================")
    print("   Windows 11 原生 DoT 安装/卸载器")
    print("   作者：xiaoyueyoqwq&Shuakami  |  日志目录：%LOCALAPPDATA%\\DoT_Installer")
    print("===============================================\n")
    print("1) 安装/更新（交互式）")
    print("2) 卸载并恢复系统原有上网配置")
    print("3) 退出")
    choice = input("请选择 [1/2/3]: ").strip()
    if choice == "1":
        do_install()
    elif choice == "2":
        do_uninstall()
    else:
        print("已退出。")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"[FATAL] {e}")
        print("发生错误，详情见日志：", LOG_PATH)
