import socket
import threading

class Client:
    def __init__(self, ip=None, port=None, received_data = None):
        self.ip = ip
        self.port = port
        self.receive_thread = threading.Thread(target=self.start_thread, args=(received_data,))
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn = None
        self.is_alive = False

    def send(self, ip, port, data):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            s.sendall(data.encode())

    def stop_receiving(self):
        self.socket.close()

    def start_receiving(self):
        self.receive_thread.start()

    def start_thread(self, received_data):
        try:
            self.is_alive = True
            self.socket.bind((self.ip, self.port))
            self.socket.listen()
            self.conn, addr = self.socket.accept()
            while True:
                recv_msg = self.conn.recv(1024)
                if not recv_msg:
                    break
                received_data(recv_msg.decode())
        except OSError as err:
            # Thread killed
            print(err)
            self.is_alive = False
            self.socket = None

