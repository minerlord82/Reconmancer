#!/usr/bin/env python3

from __future__ import annotations

import json
from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)


HOST = "127.0.0.1"
PORT = 8777


INDEX = b"""
<!doctype html>

<html>

<head>

    <title>
        Reconmancer Katana Headless Test
    </title>

</head>

<body>

    <h1>
        Katana Headless Test
    </h1>

    <a href="/normal?source=html">
        Normal HTML Link
    </a>

    <script>

        window.addEventListener(
            "DOMContentLoaded",
            () => {

                /*
                 * Create a URL dynamically so the
                 * rendered DOM contains something
                 * that was not present as a normal
                 * HTML href.
                 */

                const first =
                    "/dom";

                const second =
                    "-only";

                const link =
                    document.createElement(
                        "a"
                    );

                link.href =
                    first
                    + second
                    + "?rendered=1";

                link.textContent =
                    "DOM generated link";

                document.body.appendChild(
                    link
                );


                /*
                 * Runtime request.
                 *
                 * URL construction is split so this
                 * is useful for testing browser/XHR
                 * discovery rather than only literal
                 * static string extraction.
                 */

                const apiRoot =
                    "/api/";

                const apiName =
                    "runtime";

                fetch(
                    apiRoot
                    + apiName
                    + "?source=xhr",
                    {
                        method:
                            "POST",

                        headers:
                        {
                            "Content-Type":
                                "application/json"
                        },

                        body:
                            JSON.stringify(
                                {
                                    reconmancer:
                                        true,

                                    test:
                                        "katana-headless"
                                }
                            )
                    }
                );

            }
        );

    </script>

</body>

</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(
        self,
        format,
        *args,
    ):

        return

    def send_body(
        self,
        *,
        status: int,
        body: bytes,
        content_type: str,
    ):

        self.send_response(status)

        self.send_header(
            "Content-Type",
            content_type,
        )

        self.send_header(
            "Content-Length",
            str(len(body)),
        )

        self.end_headers()

        self.wfile.write(body)

    def do_GET(
        self,
    ):

        if self.path == "/":
            self.send_body(
                status=200,
                body=INDEX,
                content_type=("text/html; charset=utf-8"),
            )

            return

        if self.path.startswith("/normal"):
            body = b"""
                <!doctype html>
                <title>Normal Link</title>
                <h1>Normal link found</h1>
                """

            self.send_body(
                status=200,
                body=body,
                content_type=("text/html; charset=utf-8"),
            )

            return

        if self.path.startswith("/dom-only"):
            body = b"""
                <!doctype html>
                <title>DOM Only Endpoint</title>
                <h1>DOM rendered discovery worked</h1>
                """

            self.send_body(
                status=200,
                body=body,
                content_type=("text/html; charset=utf-8"),
            )

            return

        self.send_body(
            status=404,
            body=b"Not Found",
            content_type="text/plain",
        )

    def do_POST(
        self,
    ):

        if self.path.startswith("/api/runtime"):
            length = int(
                self.headers.get(
                    "Content-Length",
                    "0",
                )
            )

            request_body = self.rfile.read(length) if length else b""

            response = json.dumps(
                {
                    "ok": True,
                    "received": (
                        request_body.decode(
                            "utf-8",
                            errors="replace",
                        )
                    ),
                }
            ).encode("utf-8")

            self.send_body(
                status=200,
                body=response,
                content_type=("application/json"),
            )

            return

        self.send_body(
            status=404,
            body=b"Not Found",
            content_type="text/plain",
        )


def main():

    server = ThreadingHTTPServer(
        (
            HOST,
            PORT,
        ),
        Handler,
    )

    print(f"Katana headless test: http://{HOST}:{PORT}/")

    server.serve_forever()


if __name__ == "__main__":
    main()
