from http.server import HTTPServer, BaseHTTPRequestHandler


class Handler(BaseHTTPRequestHandler):

    def do_GET(self):

        if self.path == "/":
            body = b"Hello from my test server"
            status = 200

        elif self.path == "/admin":
            body = b"Test admin page"
            status = 200

        elif self.path == "/login":
            body = b"Test login page"
            status = 200

        else:
            body = b"Not Found"
            status = 404

        self.send_response(status)

        self.send_header(
            "Content-Type",
            "text/plain"
        )

        self.send_header(
            "Content-Length",
            str(len(body))
        )

        self.end_headers()

        self.wfile.write(body)


server = HTTPServer(
    ("127.0.0.1", 8000),
    Handler
)

print(
    "Test server running at "
    "http://127.0.0.1:8000"
)

server.serve_forever()