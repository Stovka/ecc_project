import pathlib
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog as fd
import pygubu

import os
from tkinter import messagebox
import _tkinter
from datetime import datetime

PROJECT_PATH = pathlib.Path(__file__).parent
PROJECT_UI = PROJECT_PATH / "app.ui"
BYPASS_LOGIN = True
LOG_LEVEL = 3


class Main_window:
    def __init__(self, master=None):
        self.builder = builder = pygubu.Builder()
        builder.add_resource_path(PROJECT_PATH)
        builder.add_from_file(PROJECT_UI)
        self.root = master
        self.log_root = None
        self.log_window = None
        #self.root.resizable(False, False)
        self.main_window = builder.get_object('main_window', master)
        self.main_frame = builder.get_object('frame_main', master)
        self.frame_mailbox = builder.get_object('frame_mailbox', master)

        #self.log_frame.pack(expand='true', fill='both', side='top')
        self.frame_mailbox.pack_forget()

        builder.connect_callbacks(self)

        self.logger = Logging(LOG_LEVEL)
        self.input_file_name = ""
        self.signature_file_name = ""
        self.log_text = ""
        self.log_ctr = 0
        self.mailbox_opened = False
        self.log_window_opened = False
        self.user_edit_opened = False

    def run(self):
        self.logger.log_debug("Main window stared")
        self.main_window.mainloop()

    def b_start_ecdh(self):
        print("ECDH")
        pass

    def b_open(self):
        input_file_name = self.builder.get_object("chosen_input_file")
        path = fd.askopenfilename()
        input_file_name.config(state="normal")
        input_file_name.insert(0, os.path.basename(path))
        input_file_name.config(state="readonly")
        self.input_file_name = os.path.normpath(path)

    def b_choose_user(self):
        print(self.main_window.winfo_height())
        print(self.main_window.winfo_width())

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
        if not self.user_edit_opened:
            self.user_edit_opened = True
            self.logger.log_info("edit opened")
        else:
            self.user_edit_opened = False
            self.logger.log_info("edit closed")

    def b_console(self):
        if not self.logger.is_open():
            self.logger.open_console()
        else:
            self.logger.close_console()

    def on_closing(self):
        if self.logger.is_open():
            self.logger.close_console()
        print("Saving data")
        self.root.destroy()


class Logging:

    def __init__(self, level=0):
        self.command_history = []

        self.log_root = None
        self.log_window = None
        self.log_format = ("%d-%m-%Y_%H:%M:%S")
        # 0 - error, 1 - info, 2 - debug
        if not isinstance(level, int):
            exit()
        self.level = level

    def open_console(self):
        self.log_root = tk.Tk()
        self.log_window = Log_window(self.log_root, "")
        self._update()
        self.log_window.run()

    def close_console(self):
        if self.is_open():
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
        self._update()

    def log_info(self, string):
        if self.level < 2:
            return
        self.command_history.append(f"{datetime.now().strftime(self.log_format)}:INFO:{string}")
        self._update()

    def log_error(self, string):
        self.command_history.append(f"{datetime.now().strftime(self.log_format)}:ERROR:{string}")
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

    def login(self, *args):
        password_field = self.builder.get_object("password")
        password = password_field.get()

        if BYPASS_LOGIN:
            self.unlock = True
            self.mainwindow.quit()
            return

        if not self.file_name or not password:
            messagebox.showinfo('login', 'Empty username or password')
            password_field.delete(0, "end")
            password_field.focus_set()
            return

        if self.verify_password(password, self.file_name):
            self.unlock = True
            messagebox.showinfo('login', 'Success')
            self.mainwindow.quit()

    @staticmethod
    def verify_password(password, file_path):

        if password:
            return True
        else:
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
    main_window = Main_window(root)
    root.protocol("WM_DELETE_WINDOW", main_window.on_closing)
    main_window.run()


    print("end")


if __name__ == '__main__':
    main()
