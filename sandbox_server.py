import argparse
import socket
import threading


def handle_client(conn: socket.socket, banner: str) -> None:
    with conn:
        try:
            conn.sendall((banner + "\r\n").encode("utf-8"))
        except OSError:
            pass


def run_sandbox_server(host: str, port: int, banner: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(5)
        print(f"Sandbox listener active on {host}:{port} (Ctrl+C to stop)")
        while True:
            conn, _ = srv.accept()
            thread = threading.Thread(
                target=handle_client, args=(conn, banner), daemon=True
            )
            thread.start()


def main() -> None:
    parser = argparse.ArgumentParser(description="Local TCP listener for testing port scans.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9090)
    parser.add_argument("--banner", default="Diagnostic-Mock-Service/1.0 Ready")
    args = parser.parse_args()
    try:
        run_sandbox_server(args.host, args.port, args.banner)
    except KeyboardInterrupt:
        print("\nSandbox listener stopped.")


if __name__ == "__main__":
    main()
