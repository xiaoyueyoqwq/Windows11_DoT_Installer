# -*- coding: utf-8 -*-
"""
Windows 11 原生 DoT 安装/卸载器
- 以管理员身份运行（自动检测）
- 支持多引擎、多阶段、可递归的主机名解析（DoH -> Resolve-DnsName -> getaddrinfo）
- 跟随 CNAME 链直至获取 A/AAAA；解析失败可手动输入 IPv4 继续
- 严格 TLS 预握手（SNI=主机名）；失败时可选 WARP 穿透后重试
- 关闭 DoH/DDR，启用 DoT；删除旧映射后写入新映射
- 将所有活动物理网卡 IPv4 DNS 设为选定 IP（仅此一个）
- 卸载：恢复 DoH/DDR 默认、DNS 恢复为 DHCP（或按备份恢复）、可选卸载 WARP
- 所有路径均“按任意键退出”，避免闪退
"""

from __future__ import annotations
import ctypes
import os
import ssl
import socket
import subprocess
import sys
import time
import json
import base64
import ipaddress
from datetime import datetime
from pathlib import Path

SCRIPT_VERSION = "DoT Installer v1.2.0"

APP_DIR = Path(os.environ.get("LOCALAPPDATA", ".")) / "DoT_Installer"
APP_DIR.mkdir(parents=True, exist_ok=True)
LOG_PATH = APP_DIR / ("install_%s.log" % datetime.now().strftime("%Y%m%d_%H%M%S"))
BK_DIR = Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "DoT_Installer"
BK_DIR.mkdir(parents=True, exist_ok=True)
BK_FILE = BK_DIR / "backup.json"

# 回退 DNS（非 DoH），用于 Resolve-DnsName
FALLBACK_DNS_SERVERS = ["223.5.5.5", "223.6.6.6", "1.1.1.1", "8.8.8.8"]

# 首位使用国内 DoH（仅用于“解析 DoT 目标主机名”的预解析，不影响最终写入）
PREFERRED_DOH_RESOLVERS = [
    "https://223.5.5.5/dns-query",       # AliDNS (IP端)
    "https://dns.alidns.com/dns-query",  # AliDNS (域名端)
    "https://doh.pub/dns-query",         # 腾讯
    "https://1.12.12.12/dns-query",      # 腾讯 (IP端)
    "https://1.1.1.1/dns-query",         # Cloudflare
    "https://dns.google/dns-query",      # Google
]

# -------------- 基础工具 --------------

def log(msg: str):
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def pause(msg: str = "按任意键退出…"):
    try:
        import msvcrt
        print(msg)
        msvcrt.getch()
    except Exception:
        try:
            input(msg)
        except Exception:
            pass

def die(msg: str, code: int = 1):
    log(f"[FATAL] {msg}")
    print(msg)
    pause()
    sys.exit(code)

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
    return subprocess.run(
        cmd, shell=shell, check=check,
        capture_output=capture, text=True,
        encoding="utf-8", errors="ignore"
    )

def prompt_yes_no(question: str, default_yes=True) -> bool:
    prompt = " [Y/n] " if default_yes else " [y/N] "
    while True:
        try:
            ans = input(question + prompt).strip().lower()
        except EOFError:
            return default_yes
        if not ans:
            return default_yes
        if ans in ("y", "yes", "是", "好", "确定"):
            return True
        if ans in ("n", "no", "否", "不"):
            return False
        print("请输入 y 或 n。")

def is_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False

# -------------- DoH 解析实现（带 CNAME 跟随） --------------

def _dns_build_query(qname: str, qtype: int) -> bytes:
    import random
    def encode_qname(name: str) -> bytes:
        parts = name.strip(".").split(".") if name else []
        b = bytearray()
        for p in parts:
            pb = p.encode("idna")  # 编码使用 IDNA（punycode）
            if len(pb) > 63:
                raise ValueError("标签长度超过 63")
            b.append(len(pb))
            b.extend(pb)
        b.append(0)
        return bytes(b)
    ID = random.randint(0, 0xFFFF)
    header = ID.to_bytes(2, "big") + b"\x01\x00" + b"\x00\x01\x00\x00\x00\x00\x00\x00"
    q = encode_qname(qname) + qtype.to_bytes(2, "big") + b"\x00\x01"
    return header + q

def _dns_parse_name(buf: bytes, off: int) -> tuple[str, int]:
    labels = []
    jumped = False
    start = off
    while True:
        if off >= len(buf):
            return "", off
        l = buf[off]
        if l == 0:
            off += 1
            break
        if (l & 0xC0) == 0xC0:
            if off + 1 >= len(buf):
                return "", off + 1
            ptr = ((l & 0x3F) << 8) | buf[off+1]
            if not jumped:
                start = off + 2
            off = ptr
            jumped = True
            continue
        off += 1
        label = buf[off:off+l]
        labels.append(label.decode("ascii", "strict"))
        off += l
    name = ".".join(labels)
    return name, (off if not jumped else start)

def _dns_parse_all(resp: bytes) -> dict:
    """
    返回 {'A': [..], 'AAAA': [..], 'CNAME': [targets...]}
    """
    out = {"A": [], "AAAA": [], "CNAME": []}
    if len(resp) < 12:
        return out
    qd = int.from_bytes(resp[4:6], "big")
    an = int.from_bytes(resp[6:8], "big")
    off = 12
    for _ in range(qd):
        _, off = _dns_parse_name(resp, off)
        off += 4
    for _ in range(an):
        _, off = _dns_parse_name(resp, off)
        if off + 10 > len(resp):
            break
        rtype = int.from_bytes(resp[off:off+2], "big"); off += 2
        rclass = int.from_bytes(resp[off:off+2], "big"); off += 2
        off += 4  # TTL
        rdlen = int.from_bytes(resp[off:off+2], "big"); off += 2
        rdata = resp[off:off+rdlen]; off += rdlen
        if rclass != 1:
            continue
        if rtype == 1 and rdlen == 4:  # A
            out["A"].append(".".join(str(b) for b in rdata))
        elif rtype == 28 and rdlen == 16:  # AAAA
            out["AAAA"].append(":".join(f"{rdata[i]<<8 | rdata[i+1]:x}" for i in range(0, 16, 2)))
        elif rtype == 5:  # CNAME
            cname, _ = _dns_parse_name(resp, off - rdlen)
            if cname:
                out["CNAME"].append(cname.rstrip("."))
    return out

def _doh_get(url: str, qname: str, qtype: int, timeout: float=5.0) -> dict:
    from urllib.request import Request, urlopen
    import urllib.parse
    msg = _dns_build_query(qname, qtype)
    dns_param = base64.urlsafe_b64encode(msg).rstrip(b"=").decode("ascii")
    sep = "&" if "?" in url else "?"
    full = f"{url}{sep}dns={dns_param}"
    req = Request(full, headers={
        "Accept": "application/dns-message",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "User-Agent": "DoT-Installer/1.2"
    })
    ctx = ssl.create_default_context()
    with urlopen(req, timeout=timeout, context=ctx) as resp:
        if resp.status != 200:
            return {}
        return _dns_parse_all(resp.read())

def resolve_with_doh_recursive(host: str, depth: int=5) -> list[str]:
    """
    使用国内 DoH，递归跟随 CNAME 直至得到 A/AAAA
    """
    tried = set()
    targets = [host]
    ips_v4, ips_v6 = [], []
    while targets and depth > 0:
        cur = targets.pop(0)
        depth -= 1
        if cur in tried:
            continue
        tried.add(cur)
        for u in PREFERRED_DOH_RESOLVERS:
            try:
                ansA = _doh_get(u, cur, 1) or {}
                ansAAAA = _doh_get(u, cur, 28) or {}
                a = ansA.get("A", [])
                aaaa = ansAAAA.get("AAAA", [])
                cname = list(dict.fromkeys(ansA.get("CNAME", []) + ansAAAA.get("CNAME", [])))
                if a or aaaa:
                    ips_v4.extend(a)
                    ips_v6.extend(aaaa)
                    return sorted(set(ips_v4)) + sorted(set(ips_v6))
                if cname:
                    # 跟随第一个 CNAME；其余留待后续
                    targets = cname + targets
                    break  # 换目标名再从首个 DoH 开始
            except Exception as e:
                log(f"[DoH] 解析 {cur} via {u} 失败: {e}")
        # 若所有 DoH 都失败，继续 while 进入下一个 target 或退出
    return sorted(set(ips_v4)) + sorted(set(ips_v6))

# -------------- Resolve-DnsName 回退（带 CNAME 跟随） --------------

def resolve_with_resolvedns_recursive(host: str, depth: int=5) -> list[str]:
    visited = set()
    queue = [host]
    ips_v4, ips_v6 = [], []
    while queue and depth > 0:
        cur = queue.pop(0)
        depth -= 1
        if cur in visited:
            continue
        visited.add(cur)
        for s in FALLBACK_DNS_SERVERS:
            try:
                ps = (
                    "Resolve-DnsName {host} -Server {srv} -Type A,AAAA,CNAME -DnsOnly -NoHostsFile | "
                    "Select-Object -Property QueryType,IPAddress,NameHost | ConvertTo-Json -Depth 3"
                ).format(host=cur, srv=s)
                cp = run(["powershell","-NoProfile","-Command", ps], capture=True)
                out = (cp.stdout or "").strip()
                if not out:
                    continue
                data = json.loads(out)
                rows = data if isinstance(data, list) else [data]
                cname_next = []
                for row in rows:
                    qtype = str(row.get("QueryType","")).upper()
                    ip = row.get("IPAddress")
                    nh = row.get("NameHost")
                    if qtype == "CNAME" and nh:
                        cname_next.append(str(nh).rstrip("."))
                    elif qtype == "A" and ip and is_ipv4(ip):
                        ips_v4.append(ip)
                    elif qtype == "AAAA" and ip and ":" in ip:
                        ips_v6.append(ip)
                if ips_v4 or ips_v6:
                    return sorted(set(ips_v4)) + sorted(set(ips_v6))
                if cname_next:
                    # 跟随第一个即可（常见场景只有一个）
                    queue = cname_next + queue
                    break
            except Exception as e:
                log(f"[Resolve] 解析 {cur} via {s} 失败: {e}")
    return sorted(set(ips_v4)) + sorted(set(ips_v6))

# -------------- 顶层解析 --------------

def resolve_hostname_robust(host: str, prefer_ipv4: bool=True) -> list[str]:
    if is_ipv4(host):
        return [host]
    # 1) DoH 递归
    ips = resolve_with_doh_recursive(host, depth=5)
    if not ips:
        log("[Resolve] DoH 递归解析未获得 A/AAAA，回退 Resolve-DnsName。")
        # 2) Resolve-DnsName 递归
        ips = resolve_with_resolvedns_recursive(host, depth=5)
    if not ips:
        log("[Resolve] Resolve-DnsName 仍未获得 A/AAAA，尝试系统 getaddrinfo。")
        # 3) getaddrinfo
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            cand = []
            for fam, _, _, _, sa in infos:
                ip = sa[0]
                if ":" in ip:
                    continue  # 本工具优先 IPv4
                cand.append(ip)
            ips = sorted(set(cand))
        except Exception as e:
            log(f"[Resolve] getaddrinfo 失败: {e}")
    # IPv4 优先
    if prefer_ipv4:
        ips = sorted(set([ip for ip in ips if ":" not in ip])) + [ip for ip in ips if ":" in ip]
    return ips

# -------------- TLS 预检与系统配置 --------------

def tls_preflight(ip: str, sni: str, port: int=853, timeout: float=5.0) -> tuple[bool,str,str]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert.get('subject', ()))
                cn = subject.get('commonName', '')
                not_after = cert.get('notAfter', '')
                return True, cn, not_after
    except Exception as e:
        log(f"[TLS] {ip}:{port} 预握手失败: {e}")
        return False, "", ""

def ensure_warp() -> bool:
    log("尝试静默安装并连接 Cloudflare WARP…")
    run(["winget","install","--id=Cloudflare.Warp","-e","--silent","--accept-package-agreements","--accept-source-agreements"])
    cli = Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Cloudflare" / "Cloudflare WARP" / "warp-cli.exe"
    if not cli.exists():
        cli = Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Cloudflare" / "Cloudflare WARP" / "warp-cli.exe"
    if not cli.exists():
        log("未找到 warp-cli.exe，WARP 安装可能失败。")
        return False
    run([str(cli), "--accept-tos", "register"])
    run([str(cli), "set-mode", "warp"])
    run([str(cli), "connect"])
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
    for it in data.get("ifaces", []):
        idx = it.get("InterfaceIndex")
        servers = it.get("ServerAddresses") or []
        if not idx:
            continue
        if not servers:
            run(["powershell","-NoProfile","-Command", f"Set-DnsClientServerAddress -InterfaceIndex {idx} -ResetServerAddresses"])
        else:
            addrs = " ".join(servers)
            run(["powershell","-NoProfile","-Command", f"Set-DnsClientServerAddress -InterfaceIndex {idx} -ServerAddresses {addrs}"])
    log("已根据备份恢复各接口 DNS。")

def reset_dns_to_dhcp():
    run(["powershell","-NoProfile","-Command",
         r"Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true } | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.IfIndex -ResetServerAddresses }"])

def set_global(enable_dot: bool):
    if enable_dot:
        run(["netsh","dnsclient","set","global","doh=no","dot=yes","ddr=no"])
        run(["powershell","-NoProfile","-Command",
             r"Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.HardwareInterface -eq $true} | ForEach-Object { netsh dnsclient set interface name=""$($_.Name)"" ddr=no ddrfallback=no }"])
    else:
        run(["netsh","dnsclient","set","global","doh=auto","dot=no","ddr=yes"])
        run(["powershell","-NoProfile","-Command",
             r"Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.HardwareInterface -eq $true} | ForEach-Object { netsh dnsclient set interface name=""$($_.Name)"" ddr=yes ddrfallback=yes }"])

def delete_mapping(server_ip: str):
    run(["netsh","dnsclient","delete","encryption",f"server={server_ip}","protocol=doh"])
    run(["netsh","dnsclient","delete","encryption",f"server={server_ip}","protocol=dot"])

def add_mapping(server_ip: str, dothost: str|None, udpfallback_no=True):
    args = ["netsh","dnsclient","add","encryption",f"server={server_ip}"]
    if dothost is None:
        args += [r"dothost=:"]  # 仅加密不校验主机名
    else:
        args += [f"dothost={dothost}"]
    args += ["autoupgrade=yes", f"udpfallback={'no' if udpfallback_no else 'yes'}"]
    run(args)

def set_all_nics_dns(server_ip: str):
    run(["powershell","-NoProfile","-Command",
         r"$ifaces=Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true }; "
         r"foreach($i in $ifaces){ Set-DnsClientServerAddress -InterfaceIndex $i.IfIndex -ServerAddresses " + server_ip + r" }"])

def flush_dns():
    run(["ipconfig","/flushdns"])

def show_status(server_ip: str):
    run(["netsh","dnsclient","show","global"])
    run(["netsh","dnsclient","show","encryption",f"server={server_ip}"])
    run(["netsh","dnsclient","show","state"])

# -------------- 主流程 --------------

def do_install():
    if not is_admin():
        die("请以【管理员身份】运行本程序。")

    print("=== Windows 11 原生 DoT 安装器（鲁棒性升级版） ===\n")
    print("说明：本工具将为你配置系统级 DNS-over-TLS。")
    print("提示：若网络屏蔽 853/TCP，可选择使用 Cloudflare WARP 穿透。")

    try:
        host = input("请输入 DoT 主机名（去掉 tls:// 前缀，仅域名）: ").strip()
    except EOFError:
        die("未能读取输入。")
    if not host:
        die("未输入主机名。")

    try:
        port_s = input("请输入端口（默认 853，回车使用默认）: ").strip()
    except EOFError:
        die("未能读取端口。")
    port = int(port_s) if port_s else 853

    try_warp = prompt_yes_no("如遇 853 被封，是否自动安装并连接 Cloudflare WARP 后再次尝试？", True)
    strict_only = prompt_yes_no("是否【只允许严格模式】（证书/主机名不匹配就终止，不使用仅加密模式）？", True)

    log("开始备份当前 DNS 设置…")
    backup_dns()

    log(f"解析（多引擎+递归） {host} …")
    ips = resolve_hostname_robust(host, prefer_ipv4=True)

    used_warp = False
    if not ips and try_warp:
        print("解析失败，尝试通过 WARP 再次解析…")
        if ensure_warp():
            used_warp = True
            ips = resolve_hostname_robust(host, prefer_ipv4=True)

    if not ips:
        # 引导手输 IP（严格模式仍可继续：SNI 用 host，证书照常校验）
        print("仍未解析到任何 IPv4/IPv6。")
        if prompt_yes_no("是否手动输入目标服务器 IPv4 并继续？", True):
            manual = input("请输入服务器 IPv4 地址: ").strip()
            if not is_ipv4(manual):
                die("IPv4 地址格式不正确。")
            ips = [manual]
        else:
            die("无法解析主机名。")

    print("候选 IP：", ", ".join(ips))

    chosen_ip = None
    for ip in ips:
        ok, cn, exp = tls_preflight(ip, host, port)
        if ok:
            print(f"[严格握手成功] {ip}: CN={cn}, 到期={exp}")
            chosen_ip = ip
            break
        else:
            print(f"[严格握手失败] {ip}:{port}")

    if not chosen_ip and try_warp and not used_warp:
        print("准备安装并连接 WARP 以尝试穿透 853…")
        if ensure_warp():
            used_warp = True
            for ip in ips:
                ok, cn, exp = tls_preflight(ip, host, port)
                if ok:
                    print(f"[严格握手成功] {ip}: CN={cn}, 到期={exp}")
                    chosen_ip = ip
                    break
                else:
                    print(f"[严格握手失败] {ip}:{port}")

    crypto_only = False
    if not chosen_ip:
        if strict_only:
            die("所有 IP 的严格握手均失败，且你选择了仅严格模式。")
        print("进入【仅加密模式】（不校验证书主机名）。")
        for ip in ips:
            try:
                with socket.create_connection((ip, port), timeout=3.0):
                    chosen_ip = ip
                    break
            except Exception:
                pass
        if not chosen_ip:
            die("未发现可连通 853/TCP 的 IP。请检查网络或手动开启 WARP/VPN 后重试。")
        crypto_only = True

    print(f"选定服务器 IP：{chosen_ip}")
    print("开始写入系统配置（将覆盖旧有同 IP 的 DoT/DoH 映射）…")

    set_global(enable_dot=True)
    delete_mapping(chosen_ip)
    add_mapping(chosen_ip, None if crypto_only else host, udpfallback_no=True)
    set_all_nics_dns(chosen_ip)
    flush_dns()
    show_status(chosen_ip)

    print("做一次解析测试：example.com …")
    run(["powershell","-NoProfile","-Command",
         f"Resolve-DnsName example.com -Server {chosen_ip} -Type A -NoHostsFile -DnsOnly"])

    print("\n完成。日志路径：", LOG_PATH)
    if used_warp:
        print("提示：你已启用 WARP，如不再需要可在卸载流程选择卸载它。")
    pause("操作完成。按任意键退出…")

def do_uninstall():
    if not is_admin():
        die("请以【管理员身份】运行本程序。")

    print("=== 卸载/恢复 ===")
    try:
        set_global(enable_dot=False)
        if BK_FILE.exists() and prompt_yes_no("检测到之前的 DNS 备份，是否按备份恢复？", True):
            restore_dns_from_backup()
        else:
            reset_dns_to_dhcp()
            print("已将所有活动物理网卡 DNS 恢复为 DHCP。")
        ip_guess = input("如需清理加密映射，请输入要删除映射的服务器 IP（回车跳过）: ").strip()
        if ip_guess:
            delete_mapping(ip_guess)
            print(f"已请求删除 {ip_guess} 的 DoT/DoH 映射。")
        if prompt_yes_no("是否卸载 Cloudflare WARP（若之前安装过）？", False):
            run(["winget","uninstall","--id=Cloudflare.Warp","-e"])
        flush_dns()
        print("已完成卸载/恢复。")
        pause("按任意键退出…")
    except Exception as e:
        die(f"卸载过程中出现异常：{e}")

def main():
    if not is_admin():
        die("** 请右键以【管理员身份】运行本程序，否则无法生效。**")
    print("===============================================")
    print("   Windows 11 原生 DoT 安装/卸载器")
    print("   " + SCRIPT_VERSION)
    print("   日志目录：%LOCALAPPDATA%\\DoT_Installer")
    print("===============================================\n")
    print("1) 安装/更新")
    print("2) 卸载并恢复系统原有上网配置")
    print("3) 退出")
    try:
        choice = input("请选择 [1/2/3]: ").strip()
    except EOFError:
        die("未能读取输入。")
    if choice == "1":
        try:
            do_install()
        except Exception as e:
            die(f"安装过程中发生错误：{e}")
    elif choice == "2":
        do_uninstall()
    else:
        pause("按任意键退出…")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        die(f"发生未处理的错误：{e}")
