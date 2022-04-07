import json
import pathlib
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog as fd
import pygubu

import os
from tkinter import messagebox
import _tkinter
from datetime import datetime
import cryptography

PROJECT_PATH = pathlib.Path(__file__).parent
PROJECT_UI = PROJECT_PATH / "app.ui"
BYPASS_LOGIN = False
LOG_LEVEL = 3
PRINT_CONSOLE = True


class Main_window:
    def __init__(self, master, decrypted_database, database_path):
        self.builder = builder = pygubu.Builder()
        builder.add_resource_path(PROJECT_PATH)
        builder.add_from_file(PROJECT_UI)
        self.root = master
        self.edit_root = None
        self.edit_window = None
        #self.root.resizable(False, False)
        self.main_window = builder.get_object('main_window', master)
        self.main_frame = builder.get_object('frame_main', master)
        self.frame_mailbox = builder.get_object('frame_mailbox', master)

        #self.log_frame.pack(expand='true', fill='both', side='top')
        self.frame_mailbox.pack_forget()
        self.mailbox_opened = False

        builder.connect_callbacks(self)

        self.logger = Logging(LOG_LEVEL, PRINT_CONSOLE)
        self.input_file_name = ""
        self.signature_file_name = ""
        self.log_text = ""
        self.log_ctr = 0
        #self.user_database = self.load_user_database()
        self.database = decrypted_database
        self.database_path = database_path
        self.user_database = self.load_user_database(decrypted_database)
        #self.owner = self.user_database[0]
        for user in self.user_database:
            self.logger.log_info(user.print_user())

    def run(self):
        self.logger.log_debug("Main window opened.")
        self.main_window.mainloop()

    def b_start_ecdh(self):
        alice_d = int("0xaabbccdd", 16)
        bob_d = int("0xaabbccff", 16)
        cryptography.ecdh(alice_d, bob_d)

    def b_open(self):
        input_file_name = self.builder.get_object("chosen_input_file")
        path = fd.askopenfilename()
        input_file_name.config(state="normal")
        input_file_name.insert(0, os.path.basename(path))
        input_file_name.config(state="readonly")
        self.input_file_name = os.path.normpath(path)

    def b_start_sign(self):
        print("Signing: " + self.input_file_name)
        pass

    def b_start_verify(self):
        print("Verifying: " + self.signature_file_name)
        pass

    def b_choose_signature(self):
        signature_file_name = self.builder.get_object("chosen_signature")
        path = fd.askopenfilename()
        signature_file_name.config(state="normal")
        signature_file_name.insert(0, os.path.basename(path))
        signature_file_name.config(state="readonly")
        self.input_file_name = os.path.normpath(path)

    def b_start_send(self):
        mailbox_entry = self.builder.get_object("mailbox_entry")

        self.log_ctr += 1
        self.log_text = f"ahoj {self.log_ctr} Alice sent to bob from ip 127.00.1 to 192.168.1.2 message blah blah\n" + self.log_text
        mailbox_entry.config(state="normal")
        mailbox_entry.delete(1.0,"end")
        mailbox_entry.insert(1.0, self.log_text)
        mailbox_entry.config(state="disabled")

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

    def save_database(self):
        user_database_dict = {}
        for index, user in enumerate(self.user_database):
            user_database_dict[index] = user.to_dict()

        decryption_key = self.database["password_hash"]
        ciphertext, nonce, mac = cryptography.encrypt_AES_GCM(decryption_key, json.dumps(user_database_dict))
        self.database["database"] = ciphertext.hex()
        self.database["nonce"] = nonce.hex()
        self.database["mac"] = mac.hex()
        del self.database["password_hash"]
        with open(self.database_path, "w") as f:
            json.dump(self.database, f, indent=3)

        #print(json.dumps(self.database, indent=3))



    def on_closing(self):
        if self.logger.is_open():
            self.logger.close_console()
        if self.is_edit_open():
            self.b_edit_user()
        self.logger.log_debug("Main window closing. Saving data")
        self.save_database()
        self.root.destroy()

    def is_edit_open(self):
        try:
            self.edit_root.state()
            return True
        except (_tkinter.TclError, AttributeError):
            self.edit_root, self.edit_window = None, None
            return False

    def load_user_database(self, database):
        user_database = []
        # Index 0 = owner
        for user in database["database"]:
            user_database.append(User(
                            database["database"][user]["username"],
                            database["database"][user]["name"],
                            database["database"][user]["surname"],
                            database["database"][user]["ip"],
                            database["database"][user]["pk"],
                            database["database"][user]["sk"],
                            database["database"][user]["note"]))
        return user_database

    def update_chosen_user(self):
        chosen_user_pick = self.builder.get_object("chosen_user")
        username_list = []
        for user in self.user_database:
            username_list.append(user.username)
        chosen_user_pick["values"] = username_list

    def chosen_user_clicked(self, *args):
        self.update_chosen_user()


class User:
    def __init__(self, username, name, surname, ip, pk, sk, note):
        self.username = username
        self.name = name
        self.surname = surname
        self.ip = ip
        self.pk = pk
        self.sk = sk
        self.note = note

    def to_dict(self):
        user_dict = {
            "username": self.username,
            "name": self.name,
            "surname": self.surname,
            "ip": self.ip,
            "pk": self.pk,
            "sk": self.sk,
            "note": self.note
        }
        return user_dict

    def print_user(self):
        return f"{self.username}, {self.name}, {self.surname}, {self.ip}, {self.pk}, {self.sk}, {self.note}"


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
        self.e_ip = self.builder.get_object("e_ip")
        self.e_pk = self.builder.get_object("e_pk")
        self.e_sk = self.builder.get_object("e_sk")
        self.e_note = self.builder.get_object("e_note")
        self.user_id = self.find_user_index(self.find_user(username))
        if self.user_id == None:
            # Empty user
            self.user = User("", "", "", "", "", "", "")
        else:
            self.user = self.find_user(username)
        self.e_username.insert(0, self.user.username)
        self.e_name.insert(0, self.user.name)
        self.e_surname.insert(0, self.user.surname)
        self.e_ip.insert(0, self.user.ip)
        self.e_pk.insert(0, self.user.pk)
        self.e_sk.insert(0, self.user.sk)
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
        self.user_database[self.user_id].ip = self.e_ip.get()
        self.user_database[self.user_id].pk = self.e_pk.get()
        self.user_database[self.user_id].sk = self.e_sk.get()
        self.user_database[self.user_id].note = self.e_note.get(1.0, "end")
        self.logger.log_info(f"Saving edited user: {self.e_username.get()}")

    def b_add_user(self):
        new_user = User(self.e_username.get(),
                        self.e_name.get(),
                        self.e_surname.get(),
                        self.e_ip.get(),
                        self.e_pk.get(),
                        self.e_sk.get(),
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
    def __init__(self, master=None):

        self.builder = builder = pygubu.Builder()
        builder.add_resource_path(PROJECT_PATH)
        builder.add_from_file(PROJECT_UI)
        self.mainwindow = builder.get_object('login_window', master)
        builder.connect_callbacks(self)

        self.file_name = ""
        self.password = ""
        self.unlock = False
        self.encrypted_database = ""
        self.decrypted_database = ""

        self.builder.get_object("password").focus_set()

    def run(self):
        self.mainwindow.mainloop()

    def open(self):
        file_name_field = self.builder.get_object("chosen_file")
        path = fd.askopenfilename()
        file_name_field.config(state="normal")
        file_name_field.insert(0, os.path.basename(path))
        file_name_field.config(state="readonly")
        self.file_name = os.path.normpath(path)

        if not self.load_database(self.file_name):
            messagebox.showerror('login', 'Invalid database file.')

    def login(self, *args):
        if BYPASS_LOGIN:
            self.unlock = True
            self.mainwindow.quit()
            return

        password_field = self.builder.get_object("password")
        password = password_field.get()

        if not self.file_name or not password:
            messagebox.showerror('login', 'Empty username or password')
            password_field.delete(0, "end")
            password_field.focus_set()
            return
        # Load public key
        try:
            PKx = int(self.encrypted_database["public_key"]["x"], 16)
            PKy = int(self.encrypted_database["public_key"]["y"], 16)
            nonce = bytes.fromhex(self.load_hex(self.encrypted_database["nonce"]))
            mac = bytes.fromhex(self.load_hex(self.encrypted_database["mac"]))
            encrypted_data = bytes.fromhex(self.load_hex(self.encrypted_database["database"]))
        except (TypeError, KeyError):
            messagebox.showerror('login', 'Invalid database file.')
            return

        if not cryptography.validate_password(password, (PKx, PKy)):
            messagebox.showerror('login', 'Authentication field')
            return

        decryption_key = cryptography.get_hash(password)
        decrypted_data = cryptography.decrypt_AES_GCM(decryption_key, nonce, mac, encrypted_data)
        if not decrypted_data:
            messagebox.showerror('login', 'Authentication field. MAC failed')
            return

        self.decrypted_database = self.encrypted_database
        self.decrypted_database["database"] = json.loads(decrypted_data)
        self.decrypted_database["password_hash"] = decryption_key
        del password
        self.unlock = True
        self.mainwindow.quit()

    def load_hex(self, hex_string):
        if hex_string.startswith("0x"):
            return hex_string[2:]
        else:
            return hex_string

    def load_database(self, database_path):
        try:
            with open(database_path, "r") as f:
                self.encrypted_database = json.load(f)
        except json.decoder.JSONDecodeError:
            return False
        return True


def main():
    root = tk.Tk()
    login_window = Login_window(root)
    login_window.run()
    root.destroy()

    if not login_window.unlock:
        print("end")
        exit()

    root = tk.Tk()
    main_window = Main_window(root, login_window.decrypted_database, login_window.file_name)
    root.protocol("WM_DELETE_WINDOW", main_window.on_closing)
    main_window.run()


    print("end")


if __name__ == '__main__':
    main()
