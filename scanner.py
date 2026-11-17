import argparse
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List


COMMON_SERVICES: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    9090: "Diagnostic-Mock",
}


@dataclass
class PortFinding:
    port: int
    state: str
    service_guess: str
    banner: str


def grab_banner(sock: socket.socket, host: str, port: int) -> str:
    try:
        sock.settimeout(0.6)
        if port in (80, 8000, 8080):
            probe = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii")
            sock.sendall(probe)
        raw = sock.recv(256)
        first_line = raw.decode("utf-8", errors="replace").splitlines()
        return first_line[0].strip() if first_line else ""
    except Exception:
        return ""


def probe_port(host: str, port: int, timeout: float = 0.5) -> PortFinding | None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        code = sock.connect_ex((host, port))
        if code == 0:
            banner = grab_banner(sock, host, port)
            service = COMMON_SERVICES.get(port, "Unknown")
            return PortFinding(port=port, state="OPEN", service_guess=service, banner=banner)
    return None


def scan_range(
    host: str,
    start_port: int,
    end_port: int,
    workers: int = 64,
    timeout: float = 0.5,
) -> List[PortFinding]:
    open_ports: List[PortFinding] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(probe_port, host, port, timeout): port
            for port in range(start_port, end_port + 1)
        }
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    open_ports.sort(key=lambda item: item.port)
    return open_ports


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Concurrent TCP local port auditor with lightweight banner grabbing."
    )
    parser.add_argument("--host", default="127.0.0.1", help="Target IPv4 host (default: 127.0.0.1)")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("--workers", type=int, default=64, help="Thread pool size (default: 64)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Socket timeout in seconds")
    parser.add_argument("--json-out", type=Path, default=None, help="Save findings to JSON file")
    return parser


def main() -> None:
    args = build_cli().parse_args()
    if not (1 <= args.start <= args.end <= 65535):
        raise ValueError("Port range must satisfy 1 <= start <= end <= 65535.")

    print(f"Scanning {args.host} ports {args.start}..{args.end} with {args.workers} workers...")
    findings = scan_range(args.host, args.start, args.end, args.workers, args.timeout)

    if not findings:
        print("No open TCP ports detected in the specified range.")
    else:
        print(f"{'PORT':<8} {'STATE':<8} {'SERVICE':<16} {'BANNER'}")
        print("-" * 60)
        for item in findings:
            print(f"{item.port:<8} {item.state:<8} {item.service_guess:<16} {item.banner}")

    if args.json_out:
        args.json_out.write_text(
            json.dumps([asdict(f) for f in findings], indent=2), encoding="utf-8"
        )
        print(f"Report written to {args.json_out}")


if __name__ == "__main__":
    main()
