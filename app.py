import tkinter as tk
import tkinter.font as tkFont
from tkinter import filedialog as fd


class Login:
    def __init__(self, root):
        self.logged = False
        self.password = tk.StringVar()
        self.message = tk.StringVar()
        self.filename = tk.StringVar()
        self.root = root
        #setting title
        root.title("Login")
        #setting window size
        width=361
        height=193
        screenwidth = root.winfo_screenwidth()
        screenheight = root.winfo_screenheight()
        alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
        root.geometry(alignstr)
        root.resizable(width=False, height=False)

        GMessage_945=tk.Message(root)
        ft = tkFont.Font(family='Times',size=10)
        GMessage_945["font"] = ft
        GMessage_945["fg"] = "#333333"
        GMessage_945["justify"] = "center"
        GMessage_945["text"] = "login"
        GMessage_945.place(x=130,y=10,width=100,height=30)

        GButton_156=tk.Button(root)
        GButton_156["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        GButton_156["font"] = ft
        GButton_156["fg"] = "#000000"
        GButton_156["justify"] = "center"
        GButton_156["text"] = "Vybrat soubor"
        GButton_156.place(x=70,y=50,width=100,height=30)
        GButton_156["command"] = self.GButton_156_command

        GButton_905=tk.Button(root)
        GButton_905["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        GButton_905["font"] = ft
        GButton_905["fg"] = "#000000"
        GButton_905["justify"] = "center"
        GButton_905["text"] = "Přihlásit"
        GButton_905.place(x=70,y=100,width=100,height=30)
        GButton_905["command"] = self.GButton_905_command

        GLabel_347=tk.Label(root)
        ft = tkFont.Font(family='Times',size=10)
        GLabel_347["font"] = ft
        GLabel_347["fg"] = "#333333"
        GLabel_347["justify"] = "center"
        # GLabel_347["text"] = "žádný"
        self.filename.set("žádný")
        GLabel_347["textvariable"] = self.filename
        GLabel_347.place(x=190,y=50,width=70,height=25)

        GLineEdit_991=tk.Entry(root)
        GLineEdit_991["borderwidth"] = "1px"
        ft = tkFont.Font(family='Times',size=10)
        GLineEdit_991["font"] = ft
        GLineEdit_991["fg"] = "#333333"
        GLineEdit_991["justify"] = "center"
        # GLineEdit_991["text"] = "Heslo"
        #self.password.set("")
        GLineEdit_991["textvariable"] = self.password
        GLineEdit_991.place(x=200,y=100,width=100,height=30)

        GLabel_717=tk.Label(root)
        ft = tkFont.Font(family='Times',size=10)
        GLabel_717["font"] = ft
        GLabel_717["fg"] = "#333333"
        GLabel_717["justify"] = "center"
        GLabel_717["text"] = ""
        GLabel_717["textvariable"] = self.message
        GLabel_717.place(x=70,y=140,width=230,height=30)

    def GButton_156_command(self):
        print("command")
        filename = fd.askopenfilename()
        self.filename.set(filename)


    def GButton_905_command(self):
        print("prihlaseni")
        self.login()

    # defining login function
    def login(self):
        # getting form data
        pwd = self.password.get()
        print(pwd)
        # applying empty validation
        if pwd == '':
            print("Prazdne heslo")
            self.message.set("fill the empty field!!!")
        else:
            if pwd == "123":
                self.message.set("Login success")
                print("Login success")
                self.logged = True
                self.root.destroy()
            else:
                self.message.set("Wrong username or password")
                print("Wrong username or password")

class App:
    def __init__(self, root):
        #setting title
        root.title("ECC App")
        #setting window size
        width=600
        height=500
        screenwidth = root.winfo_screenwidth()
        screenheight = root.winfo_screenheight()
        alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
        root.geometry(alignstr)
        root.resizable(width=False, height=False)

        GButton_951=tk.Button(root)
        GButton_951["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        GButton_951["font"] = ft
        GButton_951["fg"] = "#000000"
        GButton_951["justify"] = "center"
        GButton_951["text"] = "Vybrat soubor"
        GButton_951.place(x=20,y=50,width=100,height=30)
        GButton_951["command"] = self.GButton_951_command

        GButton_277=tk.Button(root)
        GButton_277["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        GButton_277["font"] = ft
        GButton_277["fg"] = "#000000"
        GButton_277["justify"] = "center"
        GButton_277["text"] = "Vybrat uživatele"
        GButton_277.place(x=20,y=100,width=100,height=30)
        GButton_277["command"] = self.GButton_277_command

        GButton_774=tk.Button(root)
        GButton_774["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        GButton_774["font"] = ft
        GButton_774["fg"] = "#000000"
        GButton_774["justify"] = "center"
        GButton_774["text"] = "Vyjednat klíč"
        GButton_774.place(x=20,y=200,width=100,height=30)
        GButton_774["command"] = self.GButton_774_command

        GButton_278=tk.Button(root)
        GButton_278["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        GButton_278["font"] = ft
        GButton_278["fg"] = "#000000"
        GButton_278["justify"] = "center"
        GButton_278["text"] = "Podepsat soubor"
        GButton_278.place(x=20,y=250,width=100,height=30)
        GButton_278["command"] = self.GButton_278_command

        GButton_99=tk.Button(root)
        GButton_99["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        GButton_99["font"] = ft
        GButton_99["fg"] = "#000000"
        GButton_99["justify"] = "center"
        GButton_99["text"] = "Ověřit podpis"
        GButton_99.place(x=140,y=250,width=100,height=30)
        GButton_99["command"] = self.GButton_99_command

        GButton_454=tk.Button(root)
        GButton_454["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        GButton_454["font"] = ft
        GButton_454["fg"] = "#000000"
        GButton_454["justify"] = "center"
        GButton_454["text"] = "Odeslat soubor"
        GButton_454.place(x=20,y=350,width=100,height=30)
        GButton_454["command"] = self.GButton_454_command

        GButton_280=tk.Button(root)
        GButton_280["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        GButton_280["font"] = ft
        GButton_280["fg"] = "#000000"
        GButton_280["justify"] = "center"
        GButton_280["text"] = "Zobrazit zprávy"
        GButton_280.place(x=140,y=350,width=100,height=30)
        GButton_280["command"] = self.GButton_280_command

        GButton_29=tk.Button(root)
        GButton_29["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        GButton_29["font"] = ft
        GButton_29["fg"] = "#000000"
        GButton_29["justify"] = "center"
        GButton_29["text"] = "Otevřít adresář"
        GButton_29.place(x=400,y=50,width=100,height=30)
        GButton_29["command"] = self.GButton_29_command

    def GButton_951_command(self):
        print("command")


    def GButton_277_command(self):
        print("command")


    def GButton_774_command(self):
        print("command")


    def GButton_278_command(self):
        print("command")


    def GButton_99_command(self):
        print("command")


    def GButton_454_command(self):
        print("command")


    def GButton_280_command(self):
        print("command")


    def GButton_29_command(self):
        print("command")

if __name__ == "__main__":
    # calling function Loginform
    root1 = tk.Tk()
    login = Login(root1)
    root1.mainloop()

    if not login.logged:
        print(f"Incorrect password")
        exit()

    root = tk.Tk()
    app = App(root)
    root.mainloop()
