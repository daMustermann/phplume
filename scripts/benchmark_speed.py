"""Reproducible loopback benchmark; never scans the LAN. No third-party packages."""
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import socket
import socketserver
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import phplume


class Healthy(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("X-Powered-By", "PHP/8.4.27")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")


class Stall(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while self.request.recv(4096):
                pass
        except OSError:
            pass


class StallServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    request_queue_size = 512


class HealthyServer(ThreadingHTTPServer):
    request_queue_size = 512


def main():
    healthy = HealthyServer(("127.0.0.1", 0), Healthy)
    stalled = StallServer(("127.0.0.1", 0), Stall)
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    for server in (healthy, stalled):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    targets = [f"http://127.0.0.1:{server.server_address[1]}/{i}" for server, count in ((healthy, 32), (stalled, 128)) for i in range(count)]
    targets += [f"http://127.0.0.1:{closed.getsockname()[1]}/{i}" for i in range(96)]
    samples = []
    try:
        for flags in ([], ["--speed"]):
            output = io.StringIO()
            started = time.monotonic()
            with contextlib.redirect_stdout(output):
                code = phplume.main([*targets, "--timeout", "0.35", "--quiet", "--json", "--no-report", *flags])
            report = json.loads(output.getvalue())
            samples.append({"mode": report["scope"]["scan_mode"], "wall_seconds": round(time.monotonic() - started, 3),
                            "http_checks": report["scope"]["completed_requests"], "tcp_checks": report["discovery"].get("connection_attempts", 0),
                            "skipped_http_checks": report["scope"]["discovery_skipped_requests"],
                            "fixed_version_results": report["summary"]["fixed_version"], "exit_code": code})
        if any(sample["fixed_version_results"] != 32 for sample in samples):
            raise RuntimeError("Fixture coverage changed under load; benchmark is inconclusive.")
        print(json.dumps({"fixture": "Loopback only: 32 healthy HTTP paths, 128 nonresponsive HTTP paths, 96 paths on a refused TCP port. Three unique TCP endpoints. Both modes use a 0.35s HTTP timeout.",
                          "samples": samples, "speedup": round(samples[0]["wall_seconds"] / samples[1]["wall_seconds"], 2),
                          "note": "Synthetic workload; real LAN gains depend on filtering, latency, available resources and service load."}, indent=2))
    finally:
        for server in (healthy, stalled):
            server.shutdown()
            server.server_close()
        closed.close()


if __name__ == "__main__":
    main()
