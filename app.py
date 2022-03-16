import tkinter as tk
import tkinter.font as tkFont



class Login:
    def __init__(self, root):
        self.root = root
        self.logged = False
        # setting title
        root.title("Login")
        # setting height and width of screen
        root.geometry("300x250")
        # declaring variable
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.message = tk.StringVar()
        self.success = False
        # Creating layout of login form
        tk.Label(root, width="300", text="Please enter details below", bg="orange", fg="white").pack()
        # Username Label
        tk.Label(root, text="Username * ").place(x=20, y=40)
        # Username textbox
        tk.Entry(root, textvariable=self.username).place(x=90, y=42)
        # Password Label
        tk.Label(root, text="Password * ").place(x=20, y=80)
        # Password textbox
        tk.Entry(root, textvariable=self.password, show="*").place(x=90, y=82)
        # Label for displaying login status[success/failed]
        tk.Label(root, text="", textvariable=self.message).place(x=95, y=100)
        # Login button
        tk.Button(root, text="Login", width=10, height=1, bg="orange", command=self.login).place(x=105, y=130)

    # defining login function
    def login(self):
        # getting form data
        uname = self.username.get()
        pwd = self.password.get()
        # applying empty validation
        if uname == '' or pwd == '':
            self.message.set("fill the empty field!!!")
        else:
            if uname == "admin" and pwd == "123":
                self.message.set("Login success")
                self.logged = True
                self.root.destroy()
            else:
                self.message.set("Wrong username or password!!!")


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
