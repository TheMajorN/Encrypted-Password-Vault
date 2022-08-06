import base64
import hashlib
import sqlite3
import uuid
from functools import partial
from tkinter import *
from tkinter import simpledialog

import pyperclip
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ===========================ENCRYPTION============================= #

backend = default_backend()  # Uses the KDF algorithm to
salt = b'42856492991'  # encrypt the master password
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryptionKey = bytearray()


def encrypt(message: bytes, key: bytes) -> bytes:  # Method to encrypt the database entries
    return Fernet(key).encrypt(message)


def decrypt(message: bytes, token: bytes) -> bytes:  # Method to decrypt the database entries
    return Fernet(token).decrypt(message)


# ============================DATABASE============================== #


with sqlite3.connect("vault.db") as db:  # Creating the database as 'vault.db'
    cursor = db.cursor()

# Uses SQL to create tables within vault.db.  This is the master password table
cursor.execute("""

CREATE TABLE IF NOT EXISTS masterPassword(
    id INTEGER PRIMARY KEY,
    password TEXT NOT NULL,
    recoveryKey TEXT NOT NULL
);

""")

# Creates the account storage table
cursor.execute("""

CREATE TABLE IF NOT EXISTS vault(
    id INTEGER PRIMARY KEY,
    usage TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);

""")


# Creates a pop-up window for the user to input account information when creating a new entry
def promptWindow(text):
    answer = simpledialog.askstring("input", text)
    return answer


# =============================SCREENS============================== #

# Creates page window
window = Tk()
window.update()
window.title("Baron Vault")


# Method to hash the password for better organization
def hashPassword(pInput):
    pHash = hashlib.sha256(pInput)
    pHash = pHash.hexdigest()

    return pHash


# Creates the screen where the user registers their master password
def registerScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("420x200")
    window.configure(bg='#000000')
    window.unbind('<Return>')

    createPassword = Label(window, text="Create Password", borderwidth=0, font='Courier 20',
                           activebackground='black', activeforeground='white', fg='white', bg='black')
    createPassword.config(anchor=CENTER)
    createPassword.pack()

    passwordInput = Entry(window, width=25, show="•", bg='#ffd100', bd=0, font='Courier 20')
    passwordInput.pack()
    passwordInput.focus()

    confirmPassword = Label(window, text="Confirm Password", borderwidth=0, font='Courier 20',
                            activebackground='black', activeforeground='white', fg='white', bg='black')
    confirmPassword.pack()

    passwordConfirmInput = Entry(window, width=25, show="•", bg='#ffd100', bd=0, font='Courier 20')
    passwordConfirmInput.pack()

    confirmMessage = Label(window, borderwidth=0, font='Courier 14',
                           activebackground='black', activeforeground='white', fg='white', bg='black')
    confirmMessage.pack()

    # Method to save the master password in the database
    def savePassword():
        if passwordInput.get() == passwordConfirmInput.get():
            sql = "DELETE FROM masterPassword WHERE id = 1"
            cursor.execute(sql)

            hashedPassword = hashPassword(passwordInput.get().encode('utf-8'))
            key = str(uuid.uuid4().hex)
            recoveryKey = hashPassword(key.encode("utf-8"))

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(passwordInput.get().encode()))

            insertPassword = """
            INSERT INTO masterPassword(password, recoveryKey)
            VALUES(?, ?)
            """
            cursor.execute(insertPassword, (hashedPassword, recoveryKey))
            db.commit()
            recoveryScreen(key)
        else:
            confirmMessage.config(text="Passwords do not match")

    enterButton = Button(window, text="Enter", command=savePassword, bg='#ffd100', font='Courier 20',
                         activebackground='#fdff00', bd=0)
    enterButton.pack(pady=10)


# Creates a screen to give the user an account recovery key in the event the user forgets their password
def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("800x300")
    window.configure(bg='#000000')
    window.unbind('<Return>')

    saveRecoveryKey = Label(window, text="Save this key somewhere\n in case you need to recover your account!\n",
                            borderwidth=0, font='Courier 14',
                            activebackground='black', activeforeground='white', fg='white', bg='black')
    saveRecoveryKey.config(anchor=CENTER)
    saveRecoveryKey.pack()

    keyDisplay = Label(window, text=key, borderwidth=0, font='Courier 20',
                       activebackground='black', activeforeground='white', fg='white', bg='#181818')
    keyDisplay.pack()

    # A simple method to copy the recovery key to the user's clipboard for easier storage
    def copyKey():
        pyperclip.copy(keyDisplay.cget("text"))

    copyKeyButton = Button(window, text="Copy Key", command=copyKey, bg='#ffd100', font='Courier 16', bd=0,
                           activebackground='#fdff00')
    copyKeyButton.pack(pady=10)

    # A simple method to return the user to the main application screen after clicking enterButton
    def done():
        vaultScreen()

    enterButton = Button(window, text="Done", command=done, bg='#ffd100', font='Courier 16', bd=0,
                         activebackground='#fdff00')
    enterButton.pack(pady=10)


# The screen in which the user inputs their saved recovery key to reclaim their account in the event of a lost password
def resetScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("420x200")
    window.configure(bg='#000000')
    window.unbind('<Return>')

    enterKey = Label(window, text="Enter Recovery Key", borderwidth=0, font='Courier 20',
                     activebackground='black', activeforeground='white', fg='white', bg='black')
    enterKey.config(anchor=CENTER)
    enterKey.pack()

    keyInput = Entry(window, width=25, bg='#ffd100', bd=0, font='Courier 20')
    keyInput.pack()
    keyInput.focus()

    keyDisplay = Label(window, text="", borderwidth=0, font='Courier 20',
                       activebackground='black', activeforeground='white', fg='white', bg='black')
    keyDisplay.pack()

    # Method to retrieve the recovery key from the database
    def getRecoveryKey():
        keyCheck = hashPassword(str(keyInput.get()).encode("utf-8"))
        cursor.execute("SELECT * FROM masterPassword WHERE id = 1 AND recoveryKey = ?", [keyCheck])
        return cursor.fetchall()

    # This method uses the above method and checks whether the key from the database matches the user inputted key
    def checkKey():
        checked = getRecoveryKey()
        if checked:
            registerScreen()
        else:
            keyInput.delete(0, 'end')
            keyDisplay.config(text="Incorrect Key!")

    checkButton = Button(window, text="Reset Password", command=checkKey, bg='#ffd100', font='Courier 14', bd=0,
                         activebackground='#fdff00')
    checkButton.pack(pady=15)


# The screen in which the user inputs their password to enter the main application screen
def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("400x200")
    window.configure(bg='#000000')
    enterPassword = Label(window, text="Enter Password", borderwidth=0, font='Courier 20',
                          activebackground='#fdff00', activeforeground='white', fg='white', bg='black')
    enterPassword.config(anchor=CENTER)
    enterPassword.pack()

    passwordInput = Entry(window, width=25, show="•", bg='#ffd100', bd=0, font='Courier 18')
    passwordInput.pack()
    passwordInput.focus()

    passwordChecker = Label(window, borderwidth=0, font='Courier 14',
                            activebackground='#fdff00', activeforeground='white', fg='white', bg='black')
    passwordChecker.pack()

    # Method to retrieve master password from the database
    def getMasterPassword():
        checkHashedPassword = hashPassword(passwordInput.get().encode('utf-8'))
        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(passwordInput.get().encode()))
        cursor.execute("SELECT * FROM masterPassword WHERE id = 1 AND password = ?",
                       [checkHashedPassword])

        return cursor.fetchall()

    # Uses the above method to check whether the retrieved password is the same as the user inputted one
    def checkPassword():
        match = getMasterPassword()

        if match:
            vaultScreen()
        else:
            passwordChecker.config(text="Incorrect")

    window.bind('<Return>', lambda event: checkPassword())

    # A method that is bound to resetButton to send the user to the reset screen
    def resetPassword():
        resetScreen()

    enterButton = Button(window, text="Enter", command=checkPassword, bg='#ffd100', font='Courier 18', bd=0, padx=5,
                         pady=5, activebackground="#fdff00")
    enterButton.pack(pady=10)

    resetButton = Button(window, text="Reset Password", command=resetPassword, bg='#ffd100', font='Courier 12', bd=0,
                         activebackground="#fdff00")
    resetButton.pack(pady=10)


begin = 0  # These variables are used when the main application displays a number of accounts on the screen.
end = 15  # The page only displays 15 accounts on the screen at a time, so these variables are manipulated
i = begin  # in the nextPage() and previousPage() methods to change which set of 15 accounts are being viewed.


# Main application screen with all of the viewable accounts
def vaultScreen():
    for widget in window.winfo_children():
        widget.destroy()

    # Method to add an account to the storage
    def addEntry():
        usage = "Site"
        username = "Username"
        password = "Password"

        usageEntry = encrypt(promptWindow(usage).encode(), encryptionKey)
        usernameEntry = encrypt(promptWindow(username).encode(), encryptionKey)
        passwordEntry = encrypt(promptWindow(password).encode(), encryptionKey)

        insertData = """
        INSERT INTO vault (usage, username, password)
        VALUES (?, ?, ?)
        """

        cursor.execute(insertData, (usageEntry, usernameEntry, passwordEntry))
        db.commit()
        global begin
        global end
        global i
        begin = 0
        end = 15
        i = begin
        vaultScreen()

    # Method to remove an account from storage
    def removeEntry(removeID):
        cursor.execute("DELETE FROM vault WHERE id = ?", (removeID,))
        db.commit()
        global begin
        global end
        global i
        begin = 0
        end = 15
        i = begin
        vaultScreen()

    # Method to flip to the next page of accounts if the user has more than 15 stored accounts
    def nextPage():
        global begin
        global end
        cursor.execute("SELECT * FROM vault")
        dbList = cursor.fetchall()
        if (begin + 15) < len(dbList):
            begin = begin + 15
            end = end + 15
            vaultScreen()

    # Method to flip to the previous page of accounts
    def previousPage():
        global begin
        global end
        global i
        if (begin - 15) >= 0:
            begin = begin - 15
            i = begin
            end = end - 15
            vaultScreen()

    window.geometry("840x770")
    window.unbind('<Return>')

    titleLabel = Label(window, text="Password Storage", borderwidth=0, font='Courier 20',
                       activebackground='black', activeforeground='white', fg='white', bg='black')
    titleLabel.grid(column=1)

    # The right button calls the nextPage method, which changes to the next 15 entries if the user has more than 15
    rightButton = Button(window, text=">", command=nextPage, borderwidth=0, font='Courier 20',
                         activebackground='#fdff00', activeforeground='white', fg='black', bg='#ffd100', bd=0)
    rightButton.grid(column=2, pady=10, row=1)

    # The left button calls the previousPage method which decreases the number of entries by 15 and refreshes the page
    leftButton = Button(window, text="<", command=previousPage, borderwidth=0, font='Courier 20',
                        activebackground='#fdff00', activeforeground='white', fg='black', bg='#ffd100', bd=0)
    leftButton.grid(column=0, pady=10, row=1)

    # This button calls the addEntry method, prompting the user to add an account
    addButton = Button(window, text="Add", command=addEntry, borderwidth=0, font='Courier 20',
                       activebackground='#fdff00', activeforeground='white', fg='black', bg='#ffd100', bd=0)
    addButton.grid(column=1, pady=10, row=1)
    usageLabel = Label(window, text="Site", borderwidth=0, font='Courier 16',
                       activebackground='#fdff00', activeforeground='white', fg='white', bg='black')
    usageLabel.grid(row=2, column=0, padx=80)

    usernameLabel = Label(window, text="Username", borderwidth=0, font='Courier 16',
                          activebackground='black', activeforeground='white', fg='white', bg='black')
    usernameLabel.grid(row=2, column=1, padx=80)

    passwordLabel = Label(window, text="Password", borderwidth=0, font='Courier 16',
                          activebackground='black', activeforeground='white', fg='white', bg='black')
    passwordLabel.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM vault")
    if cursor.fetchall() is not None:  # If there are entries in the storage
        global i
        global begin
        global end
        while i < end:  # Iterates through 15 of the entries depending on which page

            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            if len(array) == 0:
                break

            # Labels to display the accounts on each page
            lbl1 = Label(window, text=(decrypt(array[i][1], encryptionKey)), borderwidth=0, font='Calibri 14',
                         activebackground='black', activeforeground='white', fg='white', bg='#202020', padx=10, pady=5)
            lbl1.grid(column=0, row=i + 3, ipadx=20)
            lbl1 = Label(window, text=(decrypt(array[i][2], encryptionKey)), borderwidth=0, font='Calibri 14',
                         activebackground='black', activeforeground='white', fg='white', bg='#202020', padx=10, pady=5)
            lbl1.grid(column=1, row=i + 3, ipadx=20)
            lbl1 = Label(window, text=(decrypt(array[i][3], encryptionKey)), borderwidth=0, font='Calibri 14',
                         activebackground='black', activeforeground='white', fg='white', bg='#202020', padx=10, pady=5)
            lbl1.grid(column=2, row=i + 3, ipadx=20)

            # Button that calls the removeEntry method to delete an account from storage
            deleteButton = Button(window, text="Delete", command=partial(removeEntry, array[i][0]), bg='#c10003',
                                  fg='white', borderwidth=0, font='Courier 14', bd=0)
            deleteButton.grid(column=3, row=i + 3, pady=5)

            i = i + 1

            cursor.execute("SELECT * FROM vault")
            if len(cursor.fetchall()) <= i:
                break


# =====MAIN===== #

# Opens the window to the login screen if a master password is detected in the database,
# otherwise it will go to the register screen.
cursor.execute("SELECT * FROM masterPassword")
if cursor.fetchall():
    loginScreen()
else:
    registerScreen()

window.mainloop()
