from fileinput import filename
import socket
from tkinter import SEPARATOR
from tkinter.filedialog import askopenfilename

BUFFER_SIZE = 4096

SEPARATOR = ","

host = "127.0.0.1"
port = 65432

def login():
    print("Usuario: ")
    user = input(str())
    print("Contrasena: ")
    password = input(str())
    user_pass = [user, password]
    return user_pass

def openFile() -> str:
    filename = askopenfilename()
    return filename

if __name__ == "__main__":
    myInfo = login()
    myFileName = openFile()

    with open(myFileName, 'rb') as fileDataToRead:
        message = fileDataToRead.read()
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    s.sendall(f"{message}{SEPARATOR}{myInfo[0]}{SEPARATOR}{myInfo[1]}{SEPARATOR}{myFileName}".encode())

    data = s.recv(BUFFER_SIZE)
    print(data.decode())