import pathlib
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog as fd
import pygubu

import os
from tkinter import messagebox

PROJECT_PATH = pathlib.Path(__file__).parent
PROJECT_UI = PROJECT_PATH / "app.ui"


class Login_window:
    def __init__(self):

        self.builder = builder = pygubu.Builder()
        builder.add_resource_path(PROJECT_PATH)
        builder.add_from_file(PROJECT_UI)
        self.mainwindow = builder.get_object('login_window')
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
            return False


def main():
    login_window = Login_window()
    login_window.run()

    if not login_window.unlock:
        print("end")
        exit()
    print("unlocked")
    print("end")


if __name__ == '__main__':
    main()
