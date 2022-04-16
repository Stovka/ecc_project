import socket
import threading
import socketserver


class RequestHandler(socketserver.BaseRequestHandler):
    """Class for multi threaded message handling. It buffers received data. When everything is sent than it calls
    server.callback with received data."""
    def handle(self):
        to_return = bytearray()
        data = self.request.recv(1024)
        while data:
            to_return += data
            data = self.request.recv(1024)
        if self.server.receive_string:
            self.server.callback(to_return.decode())
        else:
            self.server.callback(to_return)


class Server:
    """Class for creating server. It will listen for user connections."""
    def __init__(self, ip=None, port=None, callback_mtd=None, receive_string=True):
        self.ip = ip
        self.port = port
        self.callback = callback_mtd
        self.server_thread = None
        self.socket = None
        self.server = None
        self.receive_string = receive_string
        self.is_running = False

    def _start_server(self):
        try:
            with self.server:
                self.is_running = True
                self.server.serve_forever()
        except OSError:
            # Thread killed
            self.is_running = False

    def _stop_server(self):
        try:
            self.server.shutdown()
            self.server.close()
        except AttributeError:
            pass
        self.is_running = False

    def stop_server(self):
        self._stop_server()

    def start_server(self):
        try:
            # Kill server if running
            if self.is_running:
                self._stop_server()
            if self.server_thread.is_alive():
                self._stop_server()
                self.server_thread.join()
        except AttributeError:
            pass
        # Create new server
        self.server_thread = threading.Thread(target=self._start_server)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server = socketserver.TCPServer((self.ip, self.port), RequestHandler)
        self.server.callback = self.callback
        if self.receive_string:
            self.server.receive_string = True
        else:
            self.server.receive_string = False
        self.server_thread.start()


class Client:
    """Class for sending messages by TCP."""
    @staticmethod
    def send(ip, port, bytes_data):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            s.sendall(bytes_data)

    @staticmethod
    def send_string(ip, port, string_data):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            s.sendall(string_data.encode())

