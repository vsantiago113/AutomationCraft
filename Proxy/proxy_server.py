import socket
import threading
import http.server
import socketserver
import select
from urllib.parse import urlparse, urlunparse
import requests
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(message)s')


class ProxyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_CONNECT(self):
        self._tunnel()

    def do_GET(self):
        self._proxy_request('GET')

    def do_POST(self):
        self._proxy_request('POST')

    def _tunnel(self):
        address, port = self.path.split(':')
        port = int(port)
        self.send_response(200, 'Connection Established')
        self.end_headers()

        try:
            with socket.create_connection((address, port)) as remote_sock:
                self.connection.setblocking(0)
                remote_sock.setblocking(0)
                while True:
                    ready_socks, _, _ = select.select([self.connection, remote_sock], [], [])
                    if self.connection in ready_socks:
                        data = self.connection.recv(4096)
                        if not data:
                            break
                        remote_sock.sendall(data)
                    if remote_sock in ready_socks:
                        data = remote_sock.recv(4096)
                        if not data:
                            break
                        self.connection.sendall(data)
        except Exception as e:
            logging.error(f'Error in CONNECT method: {e}')
            self.send_error(500, str(e))

    def _proxy_request(self, method):
        parsed_url = urlparse(self.path)
        scheme = 'https' if self.headers['Host'].endswith(':443') or self.path.startswith('https://') else 'http'
        url = urlunparse((scheme, self.headers['Host'], parsed_url.path, '', parsed_url.query, ''))

        headers = {key: value for key, value in self.headers.items() if key not in ('Host', 'Content-Length')}
        if 'Content-Length' in self.headers:
            headers['Content-Length'] = self.headers['Content-Length']

        try:
            response = requests.request(
                method, url, headers=headers,
                data=self.rfile.read(int(self.headers['Content-Length'])) if method == 'POST' else None,
                verify=False
            )
            self.send_response(response.status_code)
            for key, value in response.headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(response.content)
        except Exception as e:
            logging.error(f'Error in proxy request: {e}')
            self.send_error(500, str(e))


def run_proxy_server(port):
    handler = ProxyHTTPRequestHandler
    with socketserver.ThreadingTCPServer(('', port), handler) as httpd:
        logging.info(f'Starting proxy server on port {port}')
        httpd.serve_forever()


if __name__ == '__main__':
    proxy_port = 3128
    run_proxy_server(proxy_port)
