import tkinter as tk
import tkinter.font as tkFont
from tkinter import filedialog as fd

import os
import logging

PASSWORD = "123"

class Login:
    def __init__(self, root):
        self.logged = False
        self.password = tk.StringVar()
        self.message = tk.StringVar()
        self.filepath = ""
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

        M_nadpis=tk.Message(root)
        ft = tkFont.Font(family='Times',size=10)
        M_nadpis["font"] = ft
        M_nadpis["fg"] = "#333333"
        M_nadpis["justify"] = "center"
        M_nadpis["text"] = "login"
        M_nadpis.place(x=130,y=10,width=100,height=30)

        B_vybrat_soubor=tk.Button(root)
        B_vybrat_soubor["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        B_vybrat_soubor["font"] = ft
        B_vybrat_soubor["fg"] = "#000000"
        B_vybrat_soubor["justify"] = "center"
        B_vybrat_soubor["text"] = "Vybrat soubor"
        B_vybrat_soubor.place(x=70,y=50,width=100,height=30)
        B_vybrat_soubor["command"] = self.GButton_156_command

        B_prihlasit=tk.Button(root)
        B_prihlasit["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        B_prihlasit["font"] = ft
        B_prihlasit["fg"] = "#000000"
        B_prihlasit["justify"] = "center"
        B_prihlasit["text"] = "Přihlásit"
        B_prihlasit.place(x=70,y=100,width=100,height=30)
        B_prihlasit["command"] = self.GButton_905_command

        L_vybrany_soubor=tk.Label(root)
        ft = tkFont.Font(family='Times',size=10)
        L_vybrany_soubor["font"] = ft
        L_vybrany_soubor["fg"] = "#333333"
        L_vybrany_soubor["justify"] = "center"
        # L_vybrany_soubor["text"] = "žádný"
        self.filename.set("žádný")
        L_vybrany_soubor["textvariable"] = self.filename
        L_vybrany_soubor.place(x=190,y=50,width=70,height=25)

        E_heslo=tk.Entry(root)
        E_heslo["borderwidth"] = "1px"
        ft = tkFont.Font(family='Times',size=10)
        E_heslo["font"] = ft
        E_heslo["fg"] = "#333333"
        E_heslo["justify"] = "center"
        # E_heslo["text"] = "Heslo"
        #self.password.set("")
        E_heslo["textvariable"] = self.password
        E_heslo.place(x=200,y=100,width=100,height=30)

        L_message=tk.Label(root)
        ft = tkFont.Font(family='Times',size=10)
        L_message["font"] = ft
        L_message["fg"] = "#333333"
        L_message["justify"] = "center"
        L_message["text"] = ""
        L_message["textvariable"] = self.message
        L_message.place(x=70,y=140,width=230,height=30)

    def GButton_156_command(self):
        self.filepath = fd.askopenfilename()
        logger.info(f"Chosen login file: {self.filepath}")
        self.filename.set(os.path.basename(self.filepath))


    def GButton_905_command(self):
        self.login()

    # defining login function
    def login(self):
        # getting form data
        pwd = self.password.get()
        # applying empty validation
        if pwd == '':
            logger.info("Empty password entered")
            self.message.set("fill the empty field!!!")
        else:
            if pwd == PASSWORD:
                logger.info("Successful login.")
                self.message.set("Login success")
                self.logged = True
                self.root.destroy()
            else:
                logger.info("Wrong username or password entered.")
                self.message.set("Wrong username or password")

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

        B_vybrat_soubor=tk.Button(root)
        B_vybrat_soubor["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        B_vybrat_soubor["font"] = ft
        B_vybrat_soubor["fg"] = "#000000"
        B_vybrat_soubor["justify"] = "center"
        B_vybrat_soubor["text"] = "Vybrat soubor"
        B_vybrat_soubor.place(x=20,y=50,width=100,height=30)
        B_vybrat_soubor["command"] = self.GButton_951_command

        B_vybrat_uzivatele=tk.Button(root)
        B_vybrat_uzivatele["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        B_vybrat_uzivatele["font"] = ft
        B_vybrat_uzivatele["fg"] = "#000000"
        B_vybrat_uzivatele["justify"] = "center"
        B_vybrat_uzivatele["text"] = "Vybrat uživatele"
        B_vybrat_uzivatele.place(x=20,y=100,width=100,height=30)
        B_vybrat_uzivatele["command"] = self.GButton_277_command

        B_vyjednat_klic=tk.Button(root)
        B_vyjednat_klic["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        B_vyjednat_klic["font"] = ft
        B_vyjednat_klic["fg"] = "#000000"
        B_vyjednat_klic["justify"] = "center"
        B_vyjednat_klic["text"] = "Vyjednat klíč"
        B_vyjednat_klic.place(x=20,y=200,width=100,height=30)
        B_vyjednat_klic["command"] = self.GButton_774_command

        B_podepsat_soubor=tk.Button(root)
        B_podepsat_soubor["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        B_podepsat_soubor["font"] = ft
        B_podepsat_soubor["fg"] = "#000000"
        B_podepsat_soubor["justify"] = "center"
        B_podepsat_soubor["text"] = "Podepsat soubor"
        B_podepsat_soubor.place(x=20,y=250,width=100,height=30)
        B_podepsat_soubor["command"] = self.GButton_278_command

        B_overit_podpis=tk.Button(root)
        B_overit_podpis["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        B_overit_podpis["font"] = ft
        B_overit_podpis["fg"] = "#000000"
        B_overit_podpis["justify"] = "center"
        B_overit_podpis["text"] = "Ověřit podpis"
        B_overit_podpis.place(x=140,y=250,width=100,height=30)
        B_overit_podpis["command"] = self.GButton_99_command

        B_odeslat_soubor=tk.Button(root)
        B_odeslat_soubor["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        B_odeslat_soubor["font"] = ft
        B_odeslat_soubor["fg"] = "#000000"
        B_odeslat_soubor["justify"] = "center"
        B_odeslat_soubor["text"] = "Odeslat soubor"
        B_odeslat_soubor.place(x=20,y=350,width=100,height=30)
        B_odeslat_soubor["command"] = self.GButton_454_command

        B_zobrazit_zpravy=tk.Button(root)
        B_zobrazit_zpravy["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        B_zobrazit_zpravy["font"] = ft
        B_zobrazit_zpravy["fg"] = "#000000"
        B_zobrazit_zpravy["justify"] = "center"
        B_zobrazit_zpravy["text"] = "Zobrazit zprávy"
        B_zobrazit_zpravy.place(x=140,y=350,width=100,height=30)
        B_zobrazit_zpravy["command"] = self.GButton_280_command

        B_otevrit_adresar=tk.Button(root)
        B_otevrit_adresar["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        B_otevrit_adresar["font"] = ft
        B_otevrit_adresar["fg"] = "#000000"
        B_otevrit_adresar["justify"] = "center"
        B_otevrit_adresar["text"] = "Otevřít adresář"
        B_otevrit_adresar.place(x=400,y=50,width=100,height=30)
        B_otevrit_adresar["command"] = self.GButton_29_command

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

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('logger')

    logger.info("Starting login form")
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
