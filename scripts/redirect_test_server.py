#!/usr/bin/env python3

from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)


HOST = "127.0.0.1"
PORT = 8765


class Handler(BaseHTTPRequestHandler):
    def log_message(
        self,
        format,
        *args,
    ):
        return

    def send_response_body(
        self,
        *,
        status: int,
        body: bytes = b"",
        location: str | None = None,
        send_body: bool = True,
    ):

        self.send_response(status)

        if location:
            self.send_header(
                "Location",
                location,
            )

        self.send_header(
            "Content-Length",
            str(len(body)),
        )

        if body:
            self.send_header(
                "Content-Type",
                "text/html; charset=utf-8",
            )

        self.end_headers()

        if send_body and body:
            self.wfile.write(body)

    def handle_request(
        self,
        *,
        send_body: bool,
    ):

        if self.path == "/start":
            self.send_response_body(
                status=302,
                location="/step-two",
                send_body=send_body,
            )

            return

        if self.path == "/step-two":
            self.send_response_body(
                status=301,
                location="/final",
                send_body=send_body,
            )

            return

        if self.path == "/final":
            body = (
                b"<!doctype html>"
                b"<html>"
                b"<head>"
                b"<title>"
                b"Reconmancer Redirect Final"
                b"</title>"
                b"</head>"
                b"<body>"
                b"<h1>"
                b"Redirect test complete"
                b"</h1>"
                b"</body>"
                b"</html>"
            )

            self.send_response_body(
                status=200,
                body=body,
                send_body=send_body,
            )

            return

        self.send_response_body(
            status=404,
            body=b"Not Found",
            send_body=send_body,
        )

    def do_GET(
        self,
    ):

        self.handle_request(send_body=True)

    def do_HEAD(
        self,
    ):

        self.handle_request(send_body=False)


def main():

    server = ThreadingHTTPServer(
        (
            HOST,
            PORT,
        ),
        Handler,
    )

    print(f"Redirect test server: http://{HOST}:{PORT}")

    server.serve_forever()


if __name__ == "__main__":
    main()
