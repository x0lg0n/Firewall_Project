from http.server import BaseHTTPRequestHandler, HTTPServer
import logging

# Configure logging
logging.basicConfig(filename='firewall.log', level=logging.INFO)

# Define allowed and blocked rules
ALLOWED_IPS = ["127.0.0.1"]
BLOCKED_PATHS = ["/malicious"]

def is_allowed(ip, path):
    if ip not in ALLOWED_IPS:
        logging.info(f"Blocked IP: {ip}, Path: {path}")
        return False
    if any(blocked_path in path for blocked_path in BLOCKED_PATHS):
        logging.info(f"Blocked Path: {path} from IP: {ip}")
        return False
    logging.info(f"Allowed request from IP: {ip}, Path: {path}")
    return True

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        client_ip = self.client_address[0]
        request_path = self.path

        if is_allowed(client_ip, request_path):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Request allowed")
        else:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Request blocked")

def run(server_class=HTTPServer, handler_class=RequestHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting server on port {port}")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
