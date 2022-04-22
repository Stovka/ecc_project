import json
import pathlib
import time
import _tkinter
import tkinter as tk
from tkinter import messagebox
from enum import Enum
from tkinter import filedialog as fd
import pygubu
import os
from datetime import datetime

import cryptography
import networking

LOG_LEVEL = 3
PRINT_CONSOLE = True
ACCEPT_PK = True  # Trust public keys sent by HELLO_EXTEND messages. Susceptible to MitM.
ACCEPT_USER = True  # Add user to contacts after receiving HELLO message.
EXTENDED_HELLO = True  # Send more info to other users.
PROJECT_PATH = pathlib.Path(__file__).parent
PROJECT_UI = PROJECT_PATH / "app.ui"
DOWNLOADS_PATH = "Downloads/"


class Main_window:
    def __init__(self, master, decrypted_database, database_path):
        self.builder = builder = pygubu.Builder()
        builder.add_resource_path(PROJECT_PATH)
        builder.add_from_file(PROJECT_UI)
        self.root = master
        self.edit_root = None
        self.edit_window = None
        self.main_window = builder.get_object('main_window', master)
        self.main_frame = builder.get_object('frame_main', master)
        self.frame_mailbox = builder.get_object('frame_mailbox', master)
        self.frame_mailbox.pack_forget()  # Hide mailbox
        self.mailbox_opened = False
        self.online = False
        self.database = decrypted_database
        self.database_path = database_path
        self.connections = {}
        builder.connect_callbacks(self)
        self.logger = Logging(LOG_LEVEL, PRINT_CONSOLE)  # Setup logging
        self.file_name_path = ""
        self.signature_file_name_path = ""
        self.mailbox_text = ""
        self.log_ctr = 0
        self.server = networking.Server()  # Create TCP server object
        self.server.callback = self.receive_data
        self.client = networking.Client()  # Create TCP client object
        self.user_database = self.load_user_database(decrypted_database)  # Create User objects from json
        self.owner = self.user_database[0]  # Set owner
        self.owner.pk = self.database["pk"]  # Overwrite potentially invalid pk
        self.root.title(self.owner.username + " address: " + self.owner.ip_and_port + " offline")  # Set initial state
        self.builder.get_variable("l_owner").set(self.owner.username + " account")  # Set owner username to app window
        self.downloads_path = self.create_downloads(os.path.normpath(DOWNLOADS_PATH))  # Create download folder

        self.logger.log_info(f"Logged in as: {self.owner.username}")
        self.logger.log_info(f"User database: {[user.username for user in self.user_database]}")
        self.start_server()  # Try to start server (socket must by empty)

    def run(self):
        self.logger.log_debug("Main window opened.")
        self.main_window.mainloop()

    # # # # # # # # # # # # # # # # # # # # #  Buttons # # # # # # # # # # # # # # # # # # # # #
    def b_start_sign(self):
        """Method for signing files with ECDSA. It takes file (file.txt) and generates signature (file.txt.sig). It
        uses owners sk (which is password hash)."""
        if not self.file_name_path:  # Input file must by specified
            self.logger.log_error("No file to sign chosen")
            messagebox.showerror('Choose file', f"Choose file to sign first.")

        b_file = None
        with open(self.file_name_path, 'rb') as f:
            b_file = f.read()  # Load input file to memory
        # Password hash is owners sk
        signature = cryptography.ecdsa_sign(self.database["password_hash"], b_file) # Sign
        with open(self.file_name_path + ".sig", 'w') as f:  # Create signature file
            f.write(cryptography.bytes_to_hex_string(signature))  # Save signature in hex
        self.logger.log_info(f"Signature created: {self.file_name_path + '.sig'}")
        messagebox.showinfo('Signature', f"Signature created: {self.file_name_path + '.sig'}")

    def b_start_verify(self):
        """Method for verifying signatures with ECDSA. It takes two files (file.txt, file.txt.sig) and computes
        verification of signature. It uses pk of user that is selected, owners of none."""
        if not self.signature_file_name_path or not self.file_name_path:  # Input and signature files must by specified
            self.logger.log_error("No file to verify chosen")
            messagebox.showerror('Choose file', f"Choose file to verify first.")
        chosen_user = self.builder.get_object("chosen_user").get()
        if not chosen_user:
            chosen_user = self.owner.username  # If no user in specified then choose owner

        b_file = None
        with open(self.file_name_path, 'rb') as f:
            b_file = f.read()  # Load input file

        signature = None
        with open(self.signature_file_name_path, 'r') as f:
            signature = cryptography.bytes_from_hex_string(f.read())  # Load signature file

        pk = self.find_user(chosen_user).pk  # Find user in database and load public key
        if not pk:
            # Public key does not exist. Verification is not possible.
            if ACCEPT_PK and self.online:
                # Try to request public key if TRUEST_PK is True. EXTENDED_HELLO with pk will arrive only if other user
                # has EXTENDED_HELLO set to true.
                self.logger.log_info(f"User {chosen_user} does not have public key. Requesting HELLO_EXTEND.")
                ip, port = self.get_ip_and_port(self.find_user(chosen_user))
                self.send_hello_request(ip, port)
                messagebox.showwarning('ECDSA', f"Trying to request missing public key from: {chosen_user}")
                return
            self.logger.log_error(f"cannot verify signature for username: {chosen_user} missing public key")
            messagebox.showerror('Verify', f"Username: {chosen_user} missing public key.")
            return
        # Verify signature
        if cryptography.ecdsa_verify(cryptography.bytes_from_hex_string(pk), signature, b_file):
            messagebox.showinfo('Verify', f"Signature is ok.")
        else:
            messagebox.showerror('Verify', f"Signature is wrong.")

    def b_start_send(self):
        """Send file/files encrypted with ECIES encryption scheme."""
        chosen_user = self.builder.get_object("chosen_user").get()
        if not chosen_user:  # User must by specified
            self.logger.log_error("No User chosen")
            messagebox.showerror('Choose user', f"Choose user first.")
            return
        if not self.online:  # Server must be running
            self.logger.log_error("Cannot communicate while offline")
            return
        target_user = self.find_user(chosen_user)  # Find user in database
        target_ip, target_port = self.get_ip_and_port(target_user.ip_and_port)  # Get IP and port
        if not self.send_hello(target_ip, target_port):  # Test connection / synchronize ports
            messagebox.showerror('Network error', f"User: {chosen_user} on address {target_ip}:{target_port} is offline.")
            return
        if not self.file_name_path and not self.signature_file_name_path:  # At least something to send
            self.logger.log_error("No file chosen")
            messagebox.showerror('Choose file', f"Choose file first.")
            return

        if not target_user.pk:
            # Public key is missing. Sending anything is not possible.
            if ACCEPT_PK:
                self.logger.log_info("Target user does not have public key. Requesting HELLO_EXTEND.")
                self.send_hello_request(target_ip, target_port)  # Request public key
                messagebox.showwarning('ECIES', f"Trying to request missing public key from: {chosen_user}")
                return
            self.logger.log_error("Target user does not have public key")
            messagebox.showerror('ECIES', f"Target user does not have public key.")
            return

        b_file = None
        if self.file_name_path:  # Process input file
            self.logger.log_info(f"Sending file: {os.path.basename(self.file_name_path)} to: {chosen_user}")
            file_name = os.path.basename(self.file_name_path)  # Get filename
            with open(self.file_name_path, 'rb') as f:
                b_file = f.read()  # Load file to memory
            nonce, mac, cipher_text, R = self.encrypt_ecies(target_user, file_name, b_file)  # ECIES encryption
            # Construct message
            to_send = {'username': self.owner.username,
                       'action': Actions.DATA.value,
                       'nonce': cryptography.bytes_to_hex_string(nonce),
                       'mac': cryptography.bytes_to_hex_string(mac),
                       'R': cryptography.bytes_to_hex_string(R),
                       'data': cryptography.bytes_to_hex_string(cipher_text)}
            self.send_dict(target_ip, target_port, to_send)  # Send message
            self.update_mailbox(f"Sent file: {file_name} to {chosen_user}")  # Update mailbox

        if self.signature_file_name_path:  # Process signature file
            self.logger.log_info(f"Sending file: {os.path.basename(self.signature_file_name_path)} to: {chosen_user}")
            file_name = os.path.basename(self.signature_file_name_path)
            with open(self.signature_file_name_path, 'rb') as f:
                b_file = f.read()
            nonce, mac, cipher_text, R = self.encrypt_ecies(target_user, file_name, b_file)
            to_send = {'username': self.owner.username,
                       'action': Actions.DATA.value,
                       'nonce': cryptography.bytes_to_hex_string(nonce),
                       'mac': cryptography.bytes_to_hex_string(mac),
                       'R': cryptography.bytes_to_hex_string(R),
                       'data': cryptography.bytes_to_hex_string(cipher_text)}
            self.send_dict(target_ip, target_port, to_send)
            self.update_mailbox(f"Sent file: {file_name} to {chosen_user}")

    def received_file(self, data):
        """This method is called when message DATA is received."""
        user = self.find_user(data["username"])  # Load user
        if not user:
            self.logger.log_error(f"Username: {data['username']} not in contacts. Cannot decrypt file")
            messagebox.showerror('File received', f"Username: {data['username']} not in contacts. Cannot decrypt file")
        # Parse message
        to_decrypt = cryptography.bytes_from_hex_string(data["data"])
        R = cryptography.bytes_from_hex_string(data["R"])
        nonce = cryptography.bytes_from_hex_string(data["nonce"])
        mac = cryptography.bytes_from_hex_string(data["mac"])
        decrypted = self.decrypt_ecies(R, nonce, mac, to_decrypt)  # ECIES decryption
        if not decrypted:
            self.logger.log_error("Decryption Failed.")
            return

        filename, file = self.get_file_name(decrypted)  # Decode filename and file
        if not filename or not file:
            self.logger.log_error("Decoding decrypted message.")
            return
        self.logger.log_info(f"File: {filename} received from: {data['username']}")
        self.update_mailbox(f"From: {data['username']}, Received: {filename}")
        with open(os.path.join(self.downloads_path, filename), "wb") as f:
            f.write(file)

    def b_start_ecdh(self):
        """This method starts ECDH process. It computes da, Qa and sends Qa to Bob. Message is received and processed
         by ecdh_response method."""
        chosen_user = self.builder.get_object("chosen_user").get()
        if not chosen_user:  # User must by specified
            self.logger.log_error("No User chosen")
            messagebox.showerror('Choose user', f"Choose user first.")
            return
        if not self.online:  # Server must be running
            self.logger.log_error("Cannot communicate while offline")
        # Contact Bob if alive
        ip, port = self.get_ip_and_port(self.find_user(chosen_user).ip_and_port)
        if not self.send_hello(ip, port):  # Test connection / synchronize ports
            messagebox.showerror('Network error', f"User: {chosen_user} on address {ip}:{port} seams offline.")
            return
        # Starting ECDH process
        # Generate da
        random_bytes = cryptography.random_bytes(cryptography.KEY_LENGTH)
        # Calculate Qa = da * G
        point_bytes = cryptography.multiply_generator(random_bytes)
        # Save da
        self.connections[chosen_user] = {"ecdh": {"da": random_bytes}}
        # Send Qa to Bob
        to_send = {'username': self.owner.username,
                    'action': Actions.ECDH_START.value,
                    'point': cryptography.bytes_to_hex_string(point_bytes)}
        self.send_dict(ip, port, to_send)


    def ecdh_response(self, data):
        """This method finishes ECDH process. It is called twice per one ECDH process. First time when Bob receives
        Qa from Alice then it computes Qb = db * G, K = db * Qa and sends Qb to Alice. Second time when Alice receives
        Qb then it computes K = da * Qb."""
        if data["action"] == Actions.ECDH_START.value:
            # Bob received Qa
            # Generate db
            random_bytes = cryptography.random_bytes(cryptography.KEY_LENGTH)
            # Calculate Qb = db * G
            point_bytes = cryptography.multiply_generator(random_bytes)
            # Calculate shared secret as K = db * Qa
            shared_secret = cryptography.multiply_point(random_bytes, cryptography.bytes_from_hex_string(data["point"]))
            self.logger.log_info(f"Shared secret for: {data['username']}: "
                                 f"{cryptography.bytes_to_hex_string(shared_secret)}")
            self.update_mailbox(f"From: {data['username']}, "
                                f"Received: ECDH secret: {cryptography.bytes_to_hex_string(shared_secret)}")
            try:
                # Send calculated Qb to Alice
                to_send = {
                    'username': self.owner.username,
                    'action': Actions.ECDH_COMPLETE.value,
                    'point': cryptography.bytes_to_hex_string(point_bytes)}
                ip, port = self.get_ip_and_port(self.find_user(data["username"]).ip_and_port)
                self.send_dict(ip, port, to_send)
            except AttributeError:
                self.logger.log_error(f"User {data['username']} not it contacts. Cannot send ECDH reply.")
                messagebox.showerror('ECDH', f"User {data['username']} not it contacts. Cannot send ECDH reply.")
        else:  # data["action"] = Actions.ECDH_COMPLETE.value
            # Alice received Qb
            # Load da
            session = self.connections[data["username"]]["ecdh"]
            # Calculate shared secret as K = da * Qb
            shared_secret = cryptography.multiply_point(session["da"],
                                                        cryptography.bytes_from_hex_string(data["point"]))
            self.logger.log_info(f"Shared secret for: {data['username']}: "
                                 f"{cryptography.bytes_to_hex_string(shared_secret)}")
            self.update_mailbox(f"From: {data['username']}, "
                                f"Received: ECDH secret: {cryptography.bytes_to_hex_string(shared_secret)}")

    def b_choose_file(self):
        file_name = self.builder.get_object("chosen_input_file")
        path = fd.askopenfilename()
        self.update_text(file_name, os.path.basename(path))
        self.file_name_path = os.path.normpath(path)

    def b_clear_file(self):
        file_name = self.builder.get_object("chosen_input_file")
        self.update_text(file_name, "")
        self.file_name_path = ""

    def b_choose_signature(self):
        signature_file_name = self.builder.get_object("chosen_signature")
        path = fd.askopenfilename()
        self.update_text(signature_file_name, os.path.basename(path))
        self.signature_file_name_path = os.path.normpath(path)

    def b_clear_signature(self):
        signature_file_name = self.builder.get_object("chosen_signature")
        self.update_text(signature_file_name, "")
        self.signature_file_name_path = ""

    def b_start_mailbox(self):
        if not self.mailbox_opened:
            self.mailbox_opened = True
            self.frame_mailbox.pack(expand='true', fill='both', side='top')
        else:
            self.frame_mailbox.pack_forget()
            self.mailbox_opened = False

    def b_edit_user(self):
        if self.is_edit_open():
            self.edit_root.destroy()
            self.edit_root, self.edit_window = None, None
            return
        chosen_user = self.builder.get_object("chosen_user").get()
        self.edit_root = tk.Tk()
        self.edit_window = Edit_window(self.user_database, chosen_user, self.edit_root, self.logger)
        self.edit_window.run()

    def b_console(self):
        if not self.logger.is_open():
            self.logger.open_console()
        else:
            self.logger.close_console()

    # # # # # # # # # # # # # # # # # # # # #  Helper methods # # # # # # # # # # # # # # # # # # # # #
    def save_database(self):
        """This method is called when closing application. It converts database to json, encrypt it, save it."""
        user_database_dict = {}
        for index, user in enumerate(self.user_database):
            user_database_dict[index] = user.to_dict()  # User object to dictionary

        # Encrypt database
        encryption_key = self.database["password_hash"]
        ciphertext, nonce, mac = cryptography.encrypt_aes_gcm(encryption_key, json.dumps(user_database_dict))
        self.database["database"] = ciphertext.hex()
        self.database["nonce"] = nonce.hex()
        self.database["mac"] = mac.hex()
        del self.database["password_hash"]  # Remove password hash from database
        with open(self.database_path, "w") as f:
            json.dump(self.database, f, indent=3)  # Save to file

    def on_closing(self):
        if self.logger.is_open():
            self.logger.close_console()  # Close logging window
        if self.is_edit_open():
            self.b_edit_user()  # Close edit window
        self.server.stop_server()  # Stop server
        self.logger.log_debug("Main window closing. Saving data")
        self.save_database()  # Encrypt / save database
        self.root.destroy()

    def is_edit_open(self):
        try:
            self.edit_root.state()
            return True
        except (_tkinter.TclError, AttributeError):
            self.edit_root, self.edit_window = None, None
            return False

    def load_user_database(self, database):
        """Convert dict users to User objects."""
        user_database = []
        try:
            for user in database["database"]:
                user_database.append(User(
                                database["database"][user]["username"],
                                database["database"][user]["name"],
                                database["database"][user]["surname"],
                                database["database"][user]["ip"],
                                database["database"][user]["pk"],
                                database["database"][user]["note"]))
        except TypeError:
            self.logger.log_error("Database is not decrypted. Cannot start.")
            exit()
        return user_database


    def get_file_name(self, b_filename_and_file):
        """Separate file name and file bytes. Input is in format bytearray(filename.txt\nfile_bytes)"""
        buffer = ""
        for b in b_filename_and_file:
            buffer += '{!r}'.format(bytes([b]))[2:-1]
            if '\\n' in buffer:
                break
        filename = buffer[:len(buffer)-2]  # remove \n
        file = b_filename_and_file[len(buffer)-1:]
        return filename, file

    def encrypt_ecies(self, user, file_name, file_bytes):
        """ECIES encryption scheme."""
        to_encrypt = bytearray(cryptography.string_to_bytes(file_name + "\n"))
        to_encrypt += file_bytes  # to_encrypt = bytearray(filename.txt\nfile_bytes)
        # ECIES
        # Get random r
        r = cryptography.get_random_bytes(cryptography.KEY_LENGTH)
        # R = r * G
        R = cryptography.multiply_generator(r)
        # Load Qa
        Qa = cryptography.bytes_from_hex_string(user.pk)
        # S = r * Qa
        S = cryptography.multiply_point(r, Qa)
        encryption_key = cryptography.get_key_from_coordinates(S)
        cipher_text, nonce, mac = cryptography.encrypt_aes_gcm(encryption_key, to_encrypt)
        return nonce, mac, cipher_text, R

    def decrypt_ecies(self, R, nonce, mac, cipher_text):
        """ECIES decryption scheme."""
        # Load da (sk)
        da = self.database["password_hash"]
        # S = da * R
        S = cryptography.multiply_point(da, R)
        decryption_key = cryptography.get_key_from_coordinates(S)
        plain_text = cryptography.decrypt_aes_gcm(decryption_key, nonce, mac, cipher_text)
        if not plain_text:
            self.logger.log_error("ECIES Error while decrypting.")
            return None
        return plain_text

    def update_chosen_user(self):
        chosen_user_pick = self.builder.get_object("chosen_user")
        username_list = []
        for user in self.user_database:
            username_list.append(user.username)
        chosen_user_pick["values"] = username_list

    def chosen_user_clicked(self, *args):
        self.update_chosen_user()

    def find_user(self, username):
        for user in self.user_database:
            if user.username == username:
                return user
        return None

    def update_mailbox(self, text):
        self.mailbox_text = f"{datetime.now().strftime('%H:%M:%S')}: {text}\n" + self.mailbox_text
        mailbox_entry = self.builder.get_object("mailbox_entry")
        self.update_text(mailbox_entry, self.mailbox_text, True)

    @staticmethod
    def create_downloads(path):
        if not os.path.exists(path):
            os.makedirs(path)
        return path

    @staticmethod
    def update_text(obj, text, mailbox=False):
        if mailbox:
            obj.config(state="normal")
            obj.delete(1.0, "end")
            obj.insert(1.0, text)
            obj.config(state="disabled")
        else:
            obj.config(state="normal")
            obj.delete(0, "end")
            obj.insert(0, text)
            obj.config(state="readonly")


    # # # # # # # # # # # # # # # # # # # # #  Networking # # # # # # # # # # # # # # # # # # # # #
    def b_reconnect(self):
        self.online = False
        self.start_server()

    def start_server(self):
        """Method for starting / restarting TCP server."""
        self.online = False
        self.root.title(self.owner.username + " address: " + self.owner.ip_and_port + " offline")
        try:
            if self.server.is_running:
                self.logger.log_info("Stopping server")
                self.server.stop_server()  # Kill client if receiving
        except AttributeError:
            pass

        ip, port = self.get_ip_and_port(self.owner.ip_and_port)
        if not ip:
            self.server = None
            self.logger.log_error(f"Could not start listening on ip: {ip} port: {port}")
            messagebox.showerror('Network error', f"Could not start listening on ip: {ip} port: {port}")
            return

        self.server.ip = ip
        self.server.port = port
        self.server.start_server()
        time.sleep(0.5)  # Time to die
        if not self.server.is_running:
            self.server = None
            self.logger.log_error("Creating socket failed")
            messagebox.showerror('Network error', f"Could not start listening on ip: {ip} port: {port}")
            return
        self.logger.log_info(f"Listening on {ip}:{port}")
        self.root.title(self.owner.username + " address: " + self.owner.ip_and_port + " online")
        self.online = True

    def get_ip_and_port(self, ip_and_port):
        """Convert string 127.0.0.1:9999 to a string 127.0.0.1 and a int 9999."""
        try:
            ip_and_port = ip_and_port.split(":")
            ip = ip_and_port[0]
            port = int(ip_and_port[1])
            return ip, port
        except IndexError:
            self.logger.log_error(f"Invalid IP and port: {ip_and_port}")
            messagebox.showerror('Network error', f"Invalid IP and port: {ip_and_port}")
            return None, None

    def send_dict(self, ip, port, dict_data):
        self.logger.log_info(f"Sending: {Actions(dict_data['action']).name} message to: {ip}:{port}")
        try:
            self.client.send_string(ip, port, json.dumps(dict_data))
            return True
        except ConnectionRefusedError:
            self.logger.log_error(f"Connection refused for {ip}:{port}")
            return False

    def send_string(self, ip, port, string_data):
        self.logger.log_info(f"Sending: {string_data}  to: {ip}:{port}")
        try:
            self.client.send_string(ip, port, string_data)
            return True
        except ConnectionRefusedError:
            self.logger.log_error(f"Connection refused for {ip}:{port}")
            return False

    def send_hello(self, ip, port):
        """Send information about username, ip and port."""
        o_ip, o_port = self.get_ip_and_port(self.owner.ip_and_port)
        s_string = json.dumps({"username": self.owner.username,
                               "action": Actions.HELLO.value,
                               "ip": o_ip,
                               "port": o_port})
        self.logger.log_info(f"Sending HELLO to: {ip}:{port}")
        try:
            self.client.send_string(ip, port, s_string)
            return True
        except ConnectionRefusedError:
            self.logger.log_error(f"Connection refused for {ip}:{port}")
            return False

    def send_hello_full(self, ip, port):
        """Send more information including pk. It is sent only if EXTENDED_HELLO=True."""
        o_ip, o_port = self.get_ip_and_port(self.owner.ip_and_port)
        s_string = json.dumps({"username": self.owner.username,
                               "action": Actions.HELLO_EXTEND.value,
                               "ip": o_ip,
                               "port": o_port,
                               "name": self.owner.name,
                               "surname": self.owner.surname,
                               "pk": self.owner.pk})
        self.logger.log_info(f"Sending HELLO_EXTEND to: {ip}:{port}")
        try:
            self.client.send_string(ip, port, s_string)
            return True
        except ConnectionRefusedError:
            self.logger.log_error(f"Connection refused for {ip}:{port}")
            return False

    def send_hello_request(self, ip, port):
        """Request information from user. It will be sent only if TRUST_PK=True. Response containing public key
         (HELLO_EXTEND) will arrive only if target user has EXTENDED_HELLO=True."""
        o_ip, o_port = self.get_ip_and_port(self.owner.ip_and_port)
        s_string = json.dumps({"username": self.owner.username,
                               "action": Actions.REQUEST_HELLO.value,
                               "ip": o_ip,
                               "port": o_port})
        self.logger.log_info(f"Sending REQUEST_HELLO to: {ip}:{port}")
        try:
            self.client.send_string(ip, port, s_string)
            return True
        except ConnectionRefusedError:
            self.logger.log_error(f"Connection refused for {ip}:{port}")
            return False

    def receive_data(self, data):
        """Server callback method. This method receives all messages from TCP server. It calls individual response
        handlers according to the action that is in the message."""
        try:
            j_obj = json.loads(data)
        except json.decoder.JSONDecodeError:
            self.logger.log_error(f"Received corrupted data: {data}")
            return
        if j_obj["action"] == Actions.HELLO.value:
            self.handler_hello(j_obj)
        elif j_obj["action"] == Actions.DATA.value:
            self.handler_send_data(j_obj)
        elif j_obj["action"] == Actions.ECDH_START.value:
            self.handler_ecdh_start(j_obj)
        elif j_obj["action"] == Actions.ECDH_COMPLETE.value:
            self.handler_ecdh_complete(j_obj)
        elif j_obj["action"] == Actions.HELLO_EXTEND.value:
            self.handler_hello_extend(j_obj)
        elif j_obj["action"] == Actions.REQUEST_HELLO.value:
            self.handler_hello_request(j_obj)
        else:
            self.logger.log_error(f"Unknown action in message: {j_obj}")

    # Response Handlers
    def handler_hello(self, data):
        self.logger.log_info(f"HELLO message received from: {data['username']} on {data['ip']}:{data['port']}")
        user = self.find_user(data['username'])
        if not user:
            self.logger.log_error(f"Username: {data['username']} not in contacts.")
            return
        if user.username == self.owner.username: return
        user.ip_and_port = data["ip"] + ":" + str(data["port"])
    def handler_send_data(self, data):
        self.logger.log_info(f"DATA message received from: {data['username']}")
        self.received_file(data)
    def handler_ecdh_start(self, data):
        self.logger.log_info(f"ECDH_START message received from: {data['username']}")
        self.ecdh_response(data)
    def handler_ecdh_complete(self, data):
        self.logger.log_info(f"ECDH_COMPLETE message received from: {data['username']}")
        self.ecdh_response(data)
    def handler_hello_extend(self, data):
        self.logger.log_info(f"HELLO_EXTEND message received from: {data['username']}")
        user = self.find_user(data['username'])
        if not user:
            if ACCEPT_USER:
                # ADD_HELLO = True -> Add new user to database
                new_user = User(data["username"],
                                data["name"],
                                data["surname"],
                                data["ip"] + ":" + str(data["port"]),
                                data["pk"], "")
                self.user_database.append(new_user)
                self.logger.log_info(f"Creating new user: {new_user.username}")
            else:
                self.logger.log_error(f"Username: {data['username']} not in contacts.")
                return
        if user.username == self.owner.username: return
        user.ip_and_port = data["ip"] + ":" + str(data["port"])
        if ACCEPT_PK:
            # TRUST_PK = True -> Accepting PK from HELLO message
            user.pk = data["pk"]
            self.logger.log_info(f"Accepting new pk from user: {user.username}")
    def handler_hello_request(self, data):
        self.logger.log_info(f"REQUEST_HELLO message received from: {data['username']}")
        user = self.find_user(data['username'])
        if not user:
            self.logger.log_error(f"Username: {data['username']} not in contacts.")
            return
        if EXTENDED_HELLO:
            # User will receive PK
            hello_mtd = self.send_hello_full
        else:
            # User will not receive PK
            hello_mtd = self.send_hello
        if not hello_mtd(data["ip"], data["port"]):
            messagebox.showerror('Network error', f"User: {data['username']}"
                                                  f" on address {data['ip']}:{data['port']} seams offline.")
            return


class Actions(Enum):
    """Enum class representing all message types."""
    HELLO = 0
    DATA = 1
    ECDH_START = 2
    ECDH_COMPLETE = 3
    HELLO_EXTEND = 4
    REQUEST_HELLO = 5


class User:
    def __init__(self, username, name, surname, ip_and_port, pk, note):
        self.username = username
        self.name = name
        self.surname = surname
        self.ip_and_port = ip_and_port
        self.pk = pk
        self.note = note

    def to_dict(self):
        user_dict = {
            "username": self.username,
            "name": self.name,
            "surname": self.surname,
            "ip": self.ip_and_port,
            "pk": self.pk,
            "note": self.note
        }
        return user_dict


class Edit_window:
    def __init__(self, user_database, username, master, logger):
        self.builder = builder = pygubu.Builder()
        builder.add_resource_path(PROJECT_PATH)
        builder.add_from_file(PROJECT_UI)
        self.mainwindow = builder.get_object('edit_frame', master)
        self.root = master
        builder.connect_callbacks(self)

        self.logger = logger
        self.user_database = user_database
        self.username = username
        self.user = None
        self.e_username = self.builder.get_object("e_username")
        self.e_name = self.builder.get_object("e_name")
        self.e_surname = self.builder.get_object("e_surname")
        self.e_ip_and_port = self.builder.get_object("e_ip_and_port")
        self.e_pk = self.builder.get_object("e_pk")
        self.e_note = self.builder.get_object("e_note")
        self.user_id = self.find_user_index(self.find_user(username))
        if self.user_id == None:
            # Edit window opened without specifying user -> Empty user
            self.user = User("", "", "", "", "", "", "")
        else:
            self.user = self.find_user(username)
        self.e_username.insert(0, self.user.username)
        self.e_name.insert(0, self.user.name)
        self.e_surname.insert(0, self.user.surname)
        self.e_ip_and_port.insert(0, self.user.ip_and_port)
        self.e_pk.insert(0, self.user.pk)
        self.e_note.insert(1.0, self.user.note)

    def run(self):
        self.mainwindow.mainloop()

    def b_save(self):
        self.user_id = self.find_user_index(self.find_user(self.e_username.get()))
        if self.user_id == None:
            self.logger.log_error(f"User: {self.e_username.get()} does not exist")
            messagebox.showerror('Save user', f"User: {self.e_username.get()} does not exist.")
            return
        self.user_database[self.user_id].username = self.e_username.get()
        self.user_database[self.user_id].name = self.e_name.get()
        self.user_database[self.user_id].surname = self.e_surname.get()
        self.user_database[self.user_id].ip_and_port = self.e_ip_and_port.get()
        self.user_database[self.user_id].pk = self.e_pk.get()
        self.user_database[self.user_id].note = self.e_note.get(1.0, "end")
        self.logger.log_info(f"Saving edited user: {self.e_username.get()}")

    def b_add_user(self):
        new_user = User(self.e_username.get(),
                        self.e_name.get(),
                        self.e_surname.get(),
                        self.e_ip_and_port.get(),
                        self.e_pk.get(),
                        self.e_note.get(1.0, "end"))
        if new_user.username == "":
            self.logger.log_error(f"You cannot create user without username")
            messagebox.showerror('Add user', f"You cannot create user without username")
            del new_user
            return
        for user in self.user_database:
            if user.username == new_user.username:
                self.logger.log_error(f"User: {self.e_username.get()} already exists.")
                messagebox.showerror('Add user', f"User: {self.e_username.get()} already exists.")
                del new_user
                return
        self.user_database.append(new_user)
        self.logger.log_info(f"Adding new user: {self.e_username.get()}")

    def b_delete_user(self):
        self.user_id = self.find_user_index(self.find_user(self.e_username.get()))
        if self.user_id == None:
            self.logger.log_error(f"User: {self.e_username.get()} does not exist")
            messagebox.showerror('Save user', f"User: {self.e_username.get()} does not exist.")
            return
        if self.user_id == 0:
            self.logger.log_error(f"You cannot delete owner user.")
            messagebox.showerror('Delete user', f"You cannot delete owner user.")

        del self.user_database[self.user_id]
        self.logger.log_info(f"Deleting user: {self.e_username.get()}")

    def find_user(self, username):
        for user in self.user_database:
            if user.username == username:
                return user
        return None

    def find_user_index(self, user):
        try:
            return self.user_database.index(user)
        except ValueError:
            return None

class Logging:
    def __init__(self, level=0, print_console=False):
        self.command_history = []

        self.log_root = None
        self.log_window = None
        self.log_format = ("%d-%m-%Y_%H:%M:%S")
        # 0 - error, 1 - info, 2 - debug
        if not isinstance(level, int):
            print("Invalid log level (0 - error, 1 - info, 2 - debug).")
            exit()
        self.level = level
        self.print_console = print_console

    def open_console(self):
        if self.is_open():
            return
        self.log_root = tk.Tk()
        self.log_window = Log_window(self.log_root, "")
        self._update()
        self.log_window.run()

    def close_console(self):
        if not self.is_open():
            return
        self.log_root.destroy()
        self.log_root, self.log_window = None, None

    def is_open(self):
        try:
            self.log_root.state()
            return True
        except (_tkinter.TclError, AttributeError):
            self.log_root, self.log_window = None, None
            return False

    def log_debug(self, string):
        if self.level < 3:
            return
        self.command_history.append(f"{datetime.now().strftime(self.log_format)}:DEBUG:{string}")
        if self.print_console:
            print(f"{datetime.now().strftime(self.log_format)}:DEBUG:{string}")
        self._update()

    def log_info(self, string):
        if self.level < 2:
            return
        self.command_history.append(f"{datetime.now().strftime(self.log_format)}:INFO:{string}")
        if self.print_console:
            print(f"{datetime.now().strftime(self.log_format)}:INFO:{string}")
        self._update()

    def log_error(self, string):
        self.command_history.append(f"{datetime.now().strftime(self.log_format)}:ERROR:{string}")
        if self.print_console:
            print(f"{datetime.now().strftime(self.log_format)}:ERROR:{string}")
        self._update()

    def change_level(self, level):
        self.level = level

    def _update(self):
        if self.is_open():
            log = ""
            for l in self.command_history:
                log = l + "\n" + log
            self.log_window.update(log)


class Log_window:
    def __init__(self, master, log):
        self.builder = builder = pygubu.Builder()
        builder.add_resource_path(PROJECT_PATH)
        builder.add_from_file(PROJECT_UI)
        self.mainwindow = builder.get_object('log_window', master)
        builder.connect_callbacks(self)

        self.log_entry = self.builder.get_object("log_entry")
        self.log_entry.insert(1.0, log)
        self.log_entry.config(state="disabled")

    def run(self):
        self.mainwindow.mainloop()

    def update(self, log):
        self.log_entry.config(state="normal")
        self.log_entry.delete(1.0, "end")
        self.log_entry.insert(1.0, log)
        self.log_entry.config(state="disabled")


class Login_window:
    def __init__(self, master):
        self.builder = builder = pygubu.Builder()
        builder.add_resource_path(PROJECT_PATH)
        builder.add_from_file(PROJECT_UI)
        self.root = master
        self.mainwindow = builder.get_object('login_window', self.root)
        builder.connect_callbacks(self)
        self.account_root = None
        self.account_window = None

        self.file_name = ""
        self.password = ""
        self.unlock = False
        self.encrypted_database = ""
        self.decrypted_database = ""

        self.builder.get_object("password").focus_set()

    def run(self):
        self.mainwindow.mainloop()

    def open(self):
        """Open file button pressed."""
        file_name_field = self.builder.get_object("chosen_file")
        path = fd.askopenfilename()
        file_name_field.config(state="normal")
        file_name_field.delete(0, "end")
        file_name_field.insert(0, os.path.basename(path))
        file_name_field.config(state="readonly")
        self.file_name = os.path.normpath(path)

        if not self.load_database(self.file_name):
            messagebox.showerror('login', 'Invalid database file.')

    def login(self, *args):
        """Login button pressed."""
        password_field = self.builder.get_object("password")
        password = password_field.get()

        if not self.file_name or not password:
            messagebox.showerror('login', 'Empty username or password')
            password_field.delete(0, "end")
            password_field.focus_set()
            return
        # Load database
        try:
            PK = bytes.fromhex(self.load_hex(self.encrypted_database["pk"]))
            nonce = bytes.fromhex(self.load_hex(self.encrypted_database["nonce"]))
            mac = bytes.fromhex(self.load_hex(self.encrypted_database["mac"]))
            encrypted_data = bytes.fromhex(self.load_hex(self.encrypted_database["database"]))
        except (TypeError, KeyError):
            messagebox.showerror('login', 'Invalid database file.')
            return

        # Validate password
        if not cryptography.validate_password(password, PK):
            messagebox.showerror('login', 'Authentication field')
            return

        # Decrypt database
        decryption_key = cryptography.get_hash_from_string(password)
        decrypted_data = cryptography.decrypt_aes_gcm(decryption_key, nonce, mac, encrypted_data)
        decrypted_data = cryptography.string_from_bytes(decrypted_data)
        if not decrypted_data:
            messagebox.showerror('login', 'Authentication field. MAC failed')
            return

        self.decrypted_database = self.encrypted_database
        self.decrypted_database["database"] = json.loads(decrypted_data)
        self.decrypted_database["password_hash"] = decryption_key  # Save password hash
        del password  # Delete password
        self.unlock = True
        self.mainwindow.quit()

    def load_hex(self, hex_string):
        try:
            if hex_string.startswith("0x"):
                return hex_string[2:]
            else:
                return hex_string
        except AttributeError:
            return hex_string

    def load_database(self, database_path):
        """Method for loading database from file."""
        try:
            with open(database_path, "r") as f:
                self.encrypted_database = json.load(f)
        except (json.decoder.JSONDecodeError, PermissionError):
            return False
        return True

    def is_account_window_open(self):
        try:
            self.account_root.state()
            return True
        except (_tkinter.TclError, AttributeError):
            self.account_root, self.account_window = None, None
            return False

    def on_closing(self):
        if self.is_account_window_open():
            self.account_root.destroy()
            self.account_root, self.account_window = None, None
            return
        self.mainwindow.quit()

    def b_create_account(self):
        if self.is_account_window_open():
            self.account_root.destroy()
            self.account_root, self.account_window = None, None
            return
        self.account_root = tk.Tk()
        self.account_window = Account_window(self.account_root)
        self.account_window.run()


class Account_window:
    def __init__(self, master=None):
        self.builder = builder = pygubu.Builder()
        builder.add_resource_path(PROJECT_PATH)
        builder.add_from_file(PROJECT_UI)
        self.root = master
        self.mainwindow = builder.get_object('account_frame', self.root)
        builder.connect_callbacks(self)

    def run(self):
        self.mainwindow.mainloop()

    def b_create(self):
        """Method for creating login files."""
        e_username = self.builder.get_object("e_ac_username").get()
        e_password = self.builder.get_object("e_ac_password").get()
        e_ip_and_port = self.builder.get_object("e_ac_ip_and_port").get()
        if not e_username or not e_password or not e_ip_and_port:
            messagebox.showerror('Create account', 'You have to fill every field.')
            return
        file_name = e_username + ".dat"
        if os.path.exists(file_name):  # Check if account name is available.
            messagebox.showerror('Create account', f'Account {e_username} already exists.')
            return

        sk = cryptography.get_hash_from_string(e_password)  # sk is hash of password
        pk = cryptography.multiply_generator(sk)  # PK is sk * G
        # Create user database with one user (owner)
        user_database = [User(e_username, "", "", e_ip_and_port, cryptography.bytes_to_hex_string(pk), "")]

        # Create database
        database = {}
        database["pk"] = cryptography.bytes_to_hex_string(pk)
        # Convert User object to dictionary
        user_database_dict = {}
        for index, user in enumerate(user_database):
            user_database_dict[index] = user.to_dict()
        # Encrypt user database dictionary
        ciphertext, nonce, mac = cryptography.encrypt_aes_gcm(sk, json.dumps(user_database_dict))
        database["nonce"] = nonce.hex()
        database["mac"] = mac.hex()
        database["database"] = ciphertext.hex()
        with open(file_name, "w") as f:
            json.dump(database, f, indent=3)  # Save database to file as json string
        messagebox.showinfo('Create account', f'Account {e_username} created.')
        self.root.destroy()


def main():
    # Create Login window
    root = tk.Tk()
    login_window = Login_window(root)
    root.protocol("WM_DELETE_WINDOW", login_window.on_closing)
    login_window.run()
    root.destroy()

    # Check if database decryption was successful.
    if not login_window.unlock:
        exit()

    # Create Main window
    root = tk.Tk()
    main_window = Main_window(root, login_window.decrypted_database, login_window.file_name)
    root.protocol("WM_DELETE_WINDOW", main_window.on_closing)
    main_window.run()



if __name__ == '__main__':
    main()
