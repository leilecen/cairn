#!/usr/bin/env python3
"""全端口扫描 + 服务/版本检测自动化脚本

用法:
  python3 TOOLS/pipeline/full_port_scan.py --target <TARGET_IP> [--output-dir tmp/]

流程:
  1. Nmap 全端口扫描 (1-65535)
  2. 解析发现的开放端口
  3. 对开放端口进行服务/版本检测
  4. 对 HTTP 端口进行技术指纹识别
  5. 生成报告

依赖: nmap (已安装), httpx (可选)
"""

import argparse
import re
import shlex
import subprocess
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = Path(__file__).resolve().parent.parent


def run_cmd(cmd, timeout=3600):
    """执行命令并返回输出

    历史实现是 ``shell=True`` + 字符串命令：输出目录带空格时 nmap/httpx 会拿到被
    截断的参数，而且在 Windows 下要经过 cmd.exe 解释。现在统一走 argv 列表、不过 shell。
    """
    argv = shlex.split(cmd, posix=False) if isinstance(cmd, str) else list(cmd)
    argv = [a[1:-1] if len(a) > 1 and a[0] == a[-1] == '"' else a for a in argv]
    try:
        result = subprocess.run(argv, shell=False, capture_output=True, text=True, timeout=timeout)  # noqa: S603 -- argv 由本模块构造（nmap/httpx），shell=False
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", 1
    except Exception as e:
        return "", str(e), 1


def phase1_full_port_scan(target_ip, output_dir):
    """阶段 1: 全端口扫描"""
    print(f"\n{'=' * 60}")
    print(f"阶段 1: 全端口扫描 - {target_ip}")
    print(f"{'=' * 60}")

    output_file = output_dir / "nmap_allports.txt"

    # Nmap 全端口扫描命令
    cmd = f'nmap -p- -T3 --min-rate 1000 -oG "{output_file}" {target_ip}'
    print(f"执行命令: {cmd}")

    stdout, stderr, rc = run_cmd(cmd, timeout=7200)  # 2小时超时

    if rc != 0:
        print(f"扫描失败: {stderr}")
        return []

    # 解析 grepable 格式，提取开放端口
    open_ports = []
    with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            # grepable 格式: Host: x.x.x.x () Ports: 80/open/tcp//http///, 443/open/tcp//https///
            if line.startswith("Host:"):
                ports_match = re.search(r"Ports: (.+)", line)
                if ports_match:
                    ports_str = ports_match.group(1)
                    for port_info in ports_str.split(","):
                        parts = port_info.strip().split("/")
                        if len(parts) >= 2 and parts[1] == "open":
                            port_num = int(parts[0])
                            protocol = parts[2] if len(parts) > 2 else "tcp"
                            service = parts[4] if len(parts) > 4 else "unknown"
                            open_ports.append({"port": port_num, "protocol": protocol, "service": service})

    print(f"\n发现 {len(open_ports)} 个开放端口:")
    for p in open_ports:
        print(f"  {p['port']}/{p['protocol']} - {p['service']}")

    return open_ports


def phase2_service_detection(target_ip, open_ports, output_dir):
    """阶段 2: 服务/版本检测"""
    print(f"\n{'=' * 60}")
    print("阶段 2: 服务/版本检测")
    print(f"{'=' * 60}")

    if not open_ports:
        print("没有发现开放端口，跳过服务检测")
        return []

    # 构建端口列表
    port_list = ",".join([str(p["port"]) for p in open_ports])

    output_nmap = output_dir / "nmap_service.txt"
    output_xml = output_dir / "nmap_service.xml"

    # Nmap 服务检测命令
    cmd = f'nmap -sV -sC -p {port_list} -T3 -oN "{output_nmap}" -oX "{output_xml}" {target_ip}'
    print(f"执行命令: {cmd}")

    stdout, stderr, rc = run_cmd(cmd, timeout=3600)  # 1小时超时

    if rc != 0:
        print(f"服务检测失败: {stderr}")
        return []

    # 解析服务检测结果
    services = []
    with open(output_nmap, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

        # 匹配端口信息行: 80/tcp   open  http    Apache httpd 2.4.41
        pattern = r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(.*)"
        for match in re.finditer(pattern, content):
            port_num = int(match.group(1))
            protocol = match.group(2)
            service = match.group(3)
            version = match.group(4).strip()

            services.append({"port": port_num, "protocol": protocol, "service": service, "version": version})

    print("\n服务检测结果:")
    for s in services:
        print(f"  {s['port']}/{s['protocol']} - {s['service']} {s['version']}")

    return services


def phase3_http_fingerprint(target_ip, services, output_dir):
    """阶段 3: HTTP 服务深度探测"""
    print(f"\n{'=' * 60}")
    print("阶段 3: HTTP 服务深度探测")
    print(f"{'=' * 60}")

    # 筛选 HTTP 相关端口
    http_ports = []
    http_keywords = ["http", "https", "ssl/http", "ssl/https"]

    for s in services:
        if any(kw in s["service"].lower() for kw in http_keywords):
            http_ports.append(s["port"])

    if not http_ports:
        print("没有发现 HTTP 端口")
        return []

    print(f"发现 HTTP 端口: {http_ports}")

    # 尝试使用 httpx 进行技术指纹识别
    try:
        # 创建临时文件存储端口列表
        ports_file = output_dir / "http_ports.txt"
        with open(ports_file, "w") as f:
            for port in http_ports:
                f.write(f"{target_ip}:{port}\n")

        # httpx 命令
        output_httpx = output_dir / "httpx_results.txt"
        cmd = f'httpx -l "{ports_file}" -title -tech-detect -status-code -o "{output_httpx}"'
        print(f"执行命令: {cmd}")

        stdout, stderr, rc = run_cmd(cmd, timeout=600)

        if rc == 0 and Path(output_httpx).exists():
            with open(output_httpx, "r") as f:
                results = f.read()
            print(f"\nHTTP 技术指纹识别结果:\n{results}")
            return results
        else:
            print(f"httpx 执行失败或未安装: {stderr}")
            return []

    except Exception as e:
        print(f"HTTP 指纹识别失败: {e}")
        return []


def generate_report(target_ip, open_ports, services, http_results, output_dir):
    """生成扫描报告"""
    print(f"\n{'=' * 60}")
    print("生成扫描报告")
    print(f"{'=' * 60}")

    report_file = output_dir / "scan_report.md"

    with open(report_file, "w", encoding="utf-8") as f:
        f.write("# 全端口扫描报告\n\n")
        f.write(f"**目标**: {target_ip}\n")
        f.write(f"**扫描时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("**扫描工具**: Nmap 7.99\n\n")

        f.write("## 阶段 1: 全端口扫描结果\n\n")
        f.write(f"发现 **{len(open_ports)}** 个开放端口:\n\n")
        f.write("| 端口 | 协议 | 服务 |\n")
        f.write("|------|------|------|\n")
        for p in open_ports:
            f.write(f"| {p['port']} | {p['protocol']} | {p['service']} |\n")

        f.write("\n## 阶段 2: 服务/版本检测结果\n\n")
        if services:
            f.write("| 端口 | 协议 | 服务 | 版本 |\n")
            f.write("|------|------|------|------|\n")
            for s in services:
                f.write(f"| {s['port']} | {s['protocol']} | {s['service']} | {s['version']} |\n")
        else:
            f.write("未进行服务检测或无结果\n")

        f.write("\n## 阶段 3: HTTP 技术指纹识别\n\n")
        if http_results:
            f.write(f"```\n{http_results}\n```\n")
        else:
            f.write("未进行 HTTP 指纹识别或无结果\n")

        f.write("\n## 建议下一步\n\n")
        f.write("1. 对发现的 HTTP 端口进行目录枚举\n")
        f.write("2. 对发现的服务进行漏洞扫描\n")
        f.write("3. 检查默认凭据和配置问题\n")
        f.write("4. 分析 HTTP 响应头和安全头\n")

    print(f"报告已生成: {report_file}")
    return report_file


def main():
    parser = argparse.ArgumentParser(description="全端口扫描 + 服务/版本检测")
    parser.add_argument("--target", required=True, help="目标 IP 地址")
    parser.add_argument("--output-dir", default="tmp", help="输出目录")
    parser.add_argument("--skip-phase1", action="store_true", help="跳过阶段 1（如果已有全端口扫描结果）")
    parser.add_argument("--skip-phase2", action="store_true", help="跳过阶段 2（如果已有服务检测结果）")
    parser.add_argument("--skip-phase3", action="store_true", help="跳过阶段 3（HTTP 指纹识别）")

    args = parser.parse_args()

    # 创建输出目录
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)

    print("全端口扫描自动化工具")
    print(f"目标: {args.target}")
    print(f"输出目录: {output_dir}")

    # 阶段 1: 全端口扫描
    open_ports = []
    if not args.skip_phase1:
        open_ports = phase1_full_port_scan(args.target, output_dir)
    else:
        print("\n跳过阶段 1: 全端口扫描")
        # 尝试从已有结果中解析端口
        nmap_file = output_dir / "nmap_allports.txt"
        if nmap_file.exists():
            with open(nmap_file, "r") as f:
                for line in f:
                    if line.startswith("Host:"):
                        ports_match = re.search(r"Ports: (.+)", line)
                        if ports_match:
                            ports_str = ports_match.group(1)
                            for port_info in ports_str.split(","):
                                parts = port_info.strip().split("/")
                                if len(parts) >= 2 and parts[1] == "open":
                                    open_ports.append(
                                        {
                                            "port": int(parts[0]),
                                            "protocol": parts[2] if len(parts) > 2 else "tcp",
                                            "service": parts[4] if len(parts) > 4 else "unknown",
                                        }
                                    )
            print(f"从已有结果中解析到 {len(open_ports)} 个开放端口")

    # 阶段 2: 服务/版本检测
    services = []
    if not args.skip_phase2:
        services = phase2_service_detection(args.target, open_ports, output_dir)
    else:
        print("\n跳过阶段 2: 服务/版本检测")

    # 阶段 3: HTTP 技术指纹识别
    http_results = []
    if not args.skip_phase3:
        http_results = phase3_http_fingerprint(args.target, services, output_dir)
    else:
        print("\n跳过阶段 3: HTTP 技术指纹识别")

    # 生成报告
    generate_report(args.target, open_ports, services, http_results, output_dir)

    print(f"\n{'=' * 60}")
    print("扫描完成！")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
