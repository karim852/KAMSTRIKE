"""A deliberately vulnerable mock camera, used by the test suite and for demos.

It imitates a Hikvision device affected by CVE-2017-7921, with an unauthenticated snapshot
endpoint and an admin account on the documented default password. Nothing here talks to a
real device; it exists so the pipeline can be exercised without pointing it at hardware.
"""

from __future__ import annotations

import base64
import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAGIC_AUTH = "YWRtaW46MTEK"
DEFAULT_CREDS = ("admin", "12345")
#: smallest thing that passes the "is this really an image" test in the snapshot check
FAKE_JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 2048 + b"\xff\xd9"

LOGIN_PAGE = b"""<html><head><title>Hikvision Web Service</title></head>
<body><script src="/doc/page/login.asp"></script><div id="login">login</div></body></html>"""

DEVICE_INFO = b"""<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
<deviceName>IP CAMERA</deviceName><deviceID>88</deviceID>
<model>DS-2CD2042WD-I</model><serialNumber>DS-2CD2042WD-I20170101AAWR000000000</serialNumber>
<firmwareVersion>V5.4.0</firmwareVersion><firmwareReleasedDate>build 160530</firmwareReleasedDate>
</DeviceInfo>"""

USER_LIST = b"""<?xml version="1.0" encoding="UTF-8"?>
<UserList version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
<User><id>1</id><userName>admin</userName><userLevel>Administrator</userLevel>
<password>12345</password></User>
<User><id>2</id><userName>operator</userName><userLevel>Operator</userLevel>
<password>operator</password></User>
</UserList>"""


class MockCameraHandler(BaseHTTPRequestHandler):
    server_version = "App-webs/"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:  # keep the test output clean
        pass

    # ------------------------------------------------------------------ helpers
    def _send(self, status: int, body: bytes, ctype: str = "text/html",
              extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _authenticated(self) -> bool:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:]).decode("utf-8", "replace")
        except Exception:
            return False
        user, _, password = decoded.partition(":")
        return (user, password) == DEFAULT_CREDS

    def _challenge(self) -> None:
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Hikvision"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ------------------------------------------------------------------ routing
    def do_GET(self) -> None:
        path, _, query = self.path.partition("?")
        magic = f"auth={MAGIC_AUTH}" in query

        if path in ("/", "/index.html", "/doc/page/login.asp"):
            self._send(200, LOGIN_PAGE)
        elif path == "/Security/users" and magic:
            self._send(200, USER_LIST, "application/xml")
        elif path == "/System/deviceInfo" and magic:
            self._send(200, DEVICE_INFO, "application/xml")
        elif path == "/System/configurationFile" and magic:
            self._send(200, b"CONFIG" + b"\x00" * 4096, "application/octet-stream")
        elif path == "/onvif-http/snapshot":
            self._send(200, FAKE_JPEG, "image/jpeg")
        elif path == "/ISAPI/System/deviceInfo":
            if self._authenticated():
                self._send(200, DEVICE_INFO, "application/xml")
            else:
                self._challenge()
        elif path == "/ISAPI/Security/userCheck":
            if self._authenticated():
                self._send(
                    200,
                    b"<userCheck><statusValue>200</statusValue>"
                    b"<statusString>OK</statusString></userCheck>",
                    "application/xml",
                )
            else:
                self._challenge()
        else:
            self._send(404, b"<html><body>404</body></html>")

    def do_PUT(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self._send(200, b"<ResponseStatus><statusCode>1</statusCode></ResponseStatus>",
                   "application/xml")


class MockCamera:
    """Context manager that runs the mock camera on an ephemeral port."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.server = ThreadingHTTPServer((host, port), MockCameraHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def __enter__(self) -> MockCamera:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


if __name__ == "__main__":
    import sys

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    with MockCamera(port=port) as cam:
        print(f"mock vulnerable camera on http://127.0.0.1:{cam.port} - ctrl-c to stop")
        with contextlib.suppress(KeyboardInterrupt):
            threading.Event().wait()
