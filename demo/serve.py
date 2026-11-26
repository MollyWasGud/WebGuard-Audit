"""Run the deliberately WEAK demo server on 127.0.0.1:8000 (local only) so the live demo has a target.

Usage:  python -m demo.serve           (Ctrl+C to stop)
Then:   python main.py --target http://127.0.0.1:8000
"""

from http.server import HTTPServer

from demo.servers import LOOPBACK, WeakHandler

PORT = 8000

if __name__ == "__main__":
    server = HTTPServer((LOOPBACK, PORT), WeakHandler)
    print(f"[*] Weak demo server on http://{LOOPBACK}:{PORT}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    finally:
        server.server_close()
