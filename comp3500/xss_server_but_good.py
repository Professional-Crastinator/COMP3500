import http.server
import urllib.parse
import html  # ⬅️ Added for input sanitization

VALID_USERNAME = "comp3500admin"
VALID_PASSWORD = "password"

# List of (username, password) tuples
stored_credentials = []

class SimpleHTTPRequestHandler(http.server.BaseHTTPRequestHandler):

    def send_html_headers(self):
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline';")  # ⬅️ CSP header

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_html_headers()  # ⬅️ Use helper to add CSP
            self.end_headers()
            self.wfile.write(b'''
                <html>
                    <body>
                        <h2>COMP3500 Login outside of Work</h2>
                        <form action="/login" method="POST">
                            <input type="text" name="username" placeholder="Username" required><br><br>
                            <input type="password" name="password" placeholder="Password" required><br><br>
                            <input type="submit" value="Login">
                        </form>
                    </body>
                </html>
            ''')

        elif self.path == "/usernames":
            self.send_response(200)
            self.send_html_headers()  # ⬅️ Use CSP
            self.end_headers()

            self.wfile.write(b"<html><body><h1>Stored Credentials</h1><ul>")

            for username, password in stored_credentials:
                # Sanitize user input for HTML output
                safe_username = html.escape(username)
                safe_password = html.escape(password)
                self.wfile.write(f"<li>{safe_username} - {safe_password}</li>".encode())

            self.wfile.write(b"</ul></body></html>")

        else:
            self.send_response(404)
            self.send_html_headers()  # ⬅️ Use CSP
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def do_POST(self):
        if self.path == "/login":
            content_length = int(self.headers["Content-Length"])
            body = self.rfile.read(content_length).decode()
            data = urllib.parse.parse_qs(body)

            username = data.get("username", [""])[0]
            password = data.get("password", [""])[0]

            stored_credentials.append((username, password))

            if username == VALID_USERNAME and password == VALID_PASSWORD:
                self.send_response(302)
                self.send_header("Location", "/usernames")
                self.end_headers()
            else:
                self.send_response(401)
                self.send_html_headers()  # ⬅️ Use CSP
                self.end_headers()
                self.wfile.write(b'''
                    <html>
                        <body>
                            <h1>Login Failed</h1>
                            <p>Invalid username or password.</p>
                            <a href="/">Try again</a>
                        </body>
                    </html>
                ''')

def run(server_class=http.server.HTTPServer, handler_class=SimpleHTTPRequestHandler):
    server = server_class(('', 8080), handler_class)
    print("Server started on http://localhost:8080")
    server.serve_forever()

if __name__ == "__main__":
    run()
