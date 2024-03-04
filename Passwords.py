#Name: Matthew Freed
#Date: August 4th, 2023, Finished: November 14th, 2023
#Purpose: Practical Project, Password generator and manager with encryption
#Note: Make once, use forever 
#GUI: https://realpython.com/pysimplegui-python/

import secrets #Lets us use choice(), randbits(), and randbelow() to generate 
               # secure random numbers

import string #Lets us use the ascii characters for upper and lowercase
              #Digits, and and punctuation

import os #This allows us to see if any file exists and seeing if a file has any contents

from cryptography.fernet import Fernet #This will create a .key file and encrypt the accounts so that no once can edit it outside the program. https://pyshark.com/encrypt-and-decrypt-files-using-python/

import PySimpleGUI as sg #This will be the GUI for the program. https://www.pysimplegui.org

#The GUI of the program
#Color Theme
sg.theme('DarkBlack')
# All the stuff inside your window.
layout = [
            [sg.Text("Enter an email and press 'Create Account' if you do not have one already")],
            [sg.Text("Email: ")],
            [sg.Input(default_text="")], #Value[0]
            [sg.Text('What service would you like the password for?')], 
            [sg.Input(default_text="")], #Value[1]
            [[sg.Spin([i for i in range(10,17)], initial_value=10), sg.Text("Password Length")]], #values[2]
            [sg.Text("Would you like special Characters?")], 
            [sg.Radio("Yes", "RADIO1")], #values[3]
            [sg.Radio("No", "RADIO1")], #values[4]
            [sg.Text("What would you like to do?")], #Password output
            [sg.Radio("Make a new Password", "RADIO2", enable_events=True)], #values[5]
            [sg.Radio("Access Passwords", "RADIO2", enable_events=True)], #values[6]
            [sg.Radio("Overwrite a password", "RADIO2", enable_events=True)],#values[7]
            [sg.Radio("Create account", "RADIO2", enable_events=True)], #values[8]
            [sg.Text("Password: "), sg.Text(size=(45,1), key="-OUTPUT-")], #Password output
            [sg.Button("OK"), sg.Button("Cancel")] ]

# Create the Window
window = sg.Window('Password Generator & Manager', layout)

#This class creates keys,
#Writes them,
#Loads them,
#Encrypts & Decrypts
class Encryptor():

    def key_create(self):
        key = Fernet.generate_key()
        return key

    def key_write(self, key, key_name):
        with open(key_name, 'wb') as mykey:
            mykey.write(key)

    def key_load(self, key_name):
        with open(key_name, 'rb') as mykey:
            key = mykey.read()
        return key

    def file_encrypt(self, key, original_file, encrypted_file):
        
        f = Fernet(key)

        with open(original_file, 'rb') as file:
            original = file.read()

        encrypted = f.encrypt(original)

        with open (encrypted_file, 'wb') as file:
            file.write(encrypted )

    def file_decrypt(self, key, encrypted_file, decrypted_file):
        
        f = Fernet(key)

        with open(encrypted_file, 'rb') as file:
            encrypted = file.read()

        decrypted = f.decrypt(encrypted)

        with open(decrypted_file, 'wb') as file:
            file.write(decrypted)

encryptor=Encryptor()

#Method used for the Password Generator
def passwordGenerator():
    #Password generator ###########################################
    #Defining the alphabet, numbers, and special characters
    letters = string.ascii_letters
    digits = string.digits
    special_chars = string.punctuation
    num = values[2]

    #This splits the decision between having special characters or not
    if values[3]:
        alphabet = letters + digits + special_chars
        #Getting password with guaranteed numbers, letters, and special characters
        while True:
            password = ''
            for i in range(num):
                password += ''.join(secrets.choice(alphabet))
            if(any(char in special_chars for char in password) and sum(char in digits for char in password) >= 2):
                break
    elif values[4]:
        alphabet = letters + digits
            #Getting password with guaranteed numbers, letters, and special characters
        while True:
            password = ''
            for i in range(num):
                password += ''.join(secrets.choice(alphabet))
            if(sum(char in digits for char in password) >= 2):
                break

    #Password Manager################################################
    file_path = open(f"{account}.txt", "a")
    password_manager = [service, password]
    window["-OUTPUT-"].update(password)
    window.refresh()
    password_manager = ', '.join(password_manager)

    #File############################################################
    file_path.write(password_manager + "\n")
    file_path.close()
    loaded_key=encryptor.key_load(f"{account}.key")
    encryptor.file_encrypt(loaded_key, f"{account}.txt", f"{account}.txt")

while True:
    #Asks the user to enter their email once
    event, values = window.read()
    if event == sg.WIN_CLOSED or event == 'Cancel': # if user closes window or clicks cancel
        window.close()
        break
    account = values[0]
    service = values[1]

    if os.path.exists(f"{account}.key"):
        loaded_key=encryptor.key_load(f"{account}.key")

    #Decision 1, Making a password
    if values[5] == True and event == "OK":
        #Checking to see if everything is correctly filled out before continuing with the application
        if account == "" or service == "":
            window["-OUTPUT-"].update("Please fill out the service name and account name")
            continue
        elif values[3] == False and values[4] == False:
            window["-OUTPUT-"].update("Please select if you would like special characters or not")
            continue
        elif not os.path.exists(f"{account}.txt"): 
            window["-OUTPUT-"].update("Account not created yet")
            continue
        #This error checks when the file is first created so that it doesn't decrypt nothing
        if not os.path.getsize(f"{account}.txt") == 0:
            encryptor.file_decrypt(loaded_key, f"{account}.txt", f"{account}.txt")       
            service = values[1]
            f = open(f"{account}.txt", "r")
            for line in f:
                lines = line.split(", ")
            #This checks to see if a service already has a password or not
            if service in lines[0]:
                window["-OUTPUT-"].update("Service already has a password")
                loaded_key=encryptor.key_load(f"{account}.key")
                encryptor.file_encrypt(loaded_key, f"{account}.txt", f"{account}.txt")
                continue
            else: 
                passwordGenerator()
        else: 
            passwordGenerator()

    #Decision 2, Viewing passwords
    elif values[6] == True and event == "OK": 
        window.refresh()
        #Checking to see if everything is correctly filled out before continuing with the application
        if account == "" or service == "":
            window["-OUTPUT-"].update("Please fill out the service name and account name")
            continue
        elif not os.path.exists(f"{account}.txt"): 
            window["-OUTPUT-"].update("Account not created yet")
            continue 

     #Accessing the passwords############################################
        #Seeing if there is a password to read or not
        if not os.path.getsize(f"{account}.txt") == 0:
            encryptor.file_decrypt(loaded_key, f"{account}.txt", f"{account}.txt")
        else: 
            window["-OUTPUT-"].update("There are no passwords to read")
            continue

        #This sees if the service actually has a password first.
        f = open(f"{account}.txt", "r")
        service = values[1]
        line = f.read()
        if service not in line:
            window["-OUTPUT-"].update("There is no password for this service")
            encryptor.file_encrypt(loaded_key, f"{account}.txt", f"{account}.txt")
            continue

        f = open(f"{account}.txt", "r")
        service = values[1]
        for line in f:
            #This allows the user to grab the most recent password
            if service in line:
                line = line.split(", ")
                window["-OUTPUT-"].update(line[1])
        loaded_key=encryptor.key_load(f"{account}.key")
        encryptor.file_encrypt(loaded_key, f"{account}.txt", f"{account}.txt")

    #Decision 3, Overwriting the password
    elif values[7] == True and event == "OK":
    
        #Checking to see if everything is correctly filled out before continuing with the application
        if account == "" or service == "":
            window["-OUTPUT-"].update("Please fill out the service name and account name")
            continue
        if values[3] == False and values[4] == False:
            window["-OUTPUT-"].update("Please select if you would like special characters or not")
            continue
        if not os.path.exists(f"{account}.txt"): 
            window["-OUTPUT-"].update("Account not created yet")
            continue
        if os.path.getsize(f"{account}.txt") == 0:
            window["-OUTPUT-"].update("There are no passwords to overwrite")
            continue

        encryptor.file_decrypt(loaded_key, f"{account}.txt", f"{account}.txt")
        #This sees if the service actually has a password first.
        f = open(f"{account}.txt", "r")
        service = values[1]
        line = f.read()
        if service not in line:
            window["-OUTPUT-"].update("There are no passwords to read")
            encryptor.file_encrypt(loaded_key, f"{account}.txt", f"{account}.txt")
            continue
        
        #This copies all of the passwords over except the one that is being replaced
        service = values[1]
        with open(f"{account}.txt", "r") as f:
            filelines = f.readlines()
            with open(f"{account}.txt", "w") as f:
                for line in filelines:
                    if service not in line:
                        f.write(line)
        #This is the same this as in decision 1, just using the same technique
        passwordGenerator()

    #Decision 4, Create an account
    elif values[8] == True and event == "OK":
        #Seeing if the file exists, if not, a new one will be created. When you're ready for a password, a key will be created.
        while True:
            #This checks to see if the account field is filled out
            if account =="":
                window["-OUTPUT-"].update("Please fill out account name")
                break
            elif not os.path.exists(f"{account}.txt"):
                f = open(f"{account}.txt", "x")
                window["-OUTPUT-"].update("Account created successfully")
                mykey=encryptor.key_create()
                encryptor.key_write(mykey, f"{account}.key")
                break
            elif os.path.exists(f"{account}.txt"): 
                window["-OUTPUT-"].update("Account already created")
                break