# Socket Port Auditor

A concurrent TCP port scanner and service banner inspector built using Python's standard `socket` and `concurrent.futures` modules, paired with a local sandbox TCP listener for safe testing.

## Features

- **Thread-Pool Scanning**: Probes TCP port ranges concurrently using `ThreadPoolExecutor`.
- **Service & Banner Detection**: Maps well-known ports to service names and grabs initial greeting banners or HTTP headers.
- **Included Test Listener**: Includes `sandbox_server.py` to spin up a local mock service on `127.0.0.1` for verification without scanning external hosts.

## Usage

1. Start the local sandbox listener in one terminal:
   ```bash
   python auditor/sandbox_server.py --port 9090
   ```

2. Run the port auditor against localhost in another terminal:
   ```bash
   python auditor/scanner.py --host 127.0.0.1 --start 9000 --end 9100 --json-out scan.json
   ```

## Disclaimer

Intended strictly for auditing local hosts and authorized lab environments.
