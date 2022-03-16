from tkinter import *

import ecc_algorithms


def main():
    window=Tk()
    # add widgets here

    window.title('ECC App')
    window.geometry("300x200+10+20")

    ecc_algorithms.ecdh()
    ecc_algorithms.ecies()

    window.mainloop()




if __name__ == "__main__":
    main()