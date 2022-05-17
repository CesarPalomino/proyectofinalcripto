import socket
from tkinter import SEPARATOR
import nacl.utils
import nacl.secret

from nacl.signing import SigningKey
from nacl.signing import VerifyKey

_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

AUTHORIZED_USERS = {
    "pointers@fornt" : "intxp",
    "ricardo@espanol" : "trapo",
    "xd" : "a"
}

f = open("switchcaseinfo.txt", "w")


def encryptFile(InfoArchivo: bytes):
    #Encriptando el mensaje que nos envió el cliente
    #Lave
    box = nacl.secret.SecretBox(_key)
    #Encriptar la informacion
    encrypted = box.encrypt(bytes(InfoArchivo, 'utf-8'))

    f = open("switchcaseinfo.txt", "a")
    f.write(f'Datos cifrados: \n {encrypted}\n')
    f.close()

    return encrypted

def decryptFile(InfoArchivo):
    box = nacl.secret.SecretBox(_key)
    decrypted = box.decrypt(InfoArchivo)

    f = open("switchcaseinfo.txt", "a")
    f.write(f'Texto decifrado: \n{decrypted}\n')
    f.close()

    return decrypted

def signFile(encryptedFile: str):
    sign_key = SigningKey.generate()
    signedFile = sign_key.sign(encryptedFile)

    f = open("switchcaseinfo.txt", "a")
    f.write(f'Informacion firmada: \n{signedFile}\n')
    f.close()

    return signedFile, sign_key

def confirmSignedFile(signedInfo, key: SigningKey):
    verify_key = VerifyKey(key.verify_key.encode())
    res = verify_key.verify(signedInfo)

    f = open("switchcaseinfo.txt", "a")
    f.write(f'Verificar firma: \n{res}\n')
    f.close()

    return res

def login(user: str, password: str):
    file = open("logs.txt", "a")
    if user != "" and password != "":
        if user in AUTHORIZED_USERS and password in AUTHORIZED_USERS.values():
            file.write(f"El usuario {user} entro con exito\n")
            file.write("\n")
            return True
    
    file.write(f"Intento de entrada de usuario {user}\n")
    file.write("\n")
    file.close()
    return False

def accessLog():
    f = open("logs.txt", "r")
    print(f.read())
    f.close()

if __name__ == "__main__":
    BUFFER_SIZE = 4096

    host = "127.0.0.1"
    port = 65432

    SEPARATOR = ","

    s = socket.socket()
    s.bind((host, port))
    s.listen()

    client, address = s.accept()
    print(f"Connectado a {address}")

    everything = client.recv(BUFFER_SIZE).decode()
    message, user, password, filename = everything.split(SEPARATOR)

    if not login(user, password):
        client.sendall(f"El usuario {user} no esta autorizado".encode())\
    
    else:
        print("Archivo cifrado")
        archivoCifrado = encryptFile(message)
        client.sendall(f'Archivo cifrado: \n{archivoCifrado}\n'.encode())

        print("Descifrar archivo")
        archivoDescifrado = decryptFile(archivoCifrado)
        client.sendall(f'Archivo descifrado: \n{archivoDescifrado}\n'.encode())

        print("Firmar archivo")
        infoFirmada, key = signFile(archivoCifrado)

        print("Verificar firma")
        infoVerificada = confirmSignedFile(infoFirmada, key)

        accessLog()

    s.close()