# Laboratorio 9 Recuperativo Seguridad Informatcia
# Fabian Urra y Jose Castillo

import socket, json
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
import os
import hashlib

def cifrar_rot_n(mensaje, n):
    resultado = ""
    for caracter in mensaje:
        if caracter.isalpha():
            if caracter.isupper():
                resultado += chr((ord(caracter) + n - 65) % 26 + 65)
            else:
                resultado += chr((ord(caracter) + n - 97) % 26 + 97)
        else:
            resultado += caracter
    return resultado

def descifrar_rot_n(mensaje, n):
    return cifrar_rot_n(mensaje, -n)

def escoger_b(num):
    aux = True
    escoger_b = int(input("Ingrese su numero b mayor que cero y menor que p: "))
    while(aux):
        if escoger_b> 0 and escoger_b <num:
            print("Numero a cumple las condiciones")
            return escoger_b
        else:
            print("Intentelo nuevamente")
            escoger_b = int(input("Ingrese su numero b mayor que cero y menor que p: "))

def diffie_hellamn(g,b,p):
    B = (g**b) % p
    return B

def encriptar_aes256(clave, texto_plano):
    clave_bytes = clave.to_bytes(32, byteorder='big')

    iv = os.urandom(16)

    cifrador = Cipher(algorithms.AES(clave_bytes), modes.CFB(iv), backend=default_backend())

    encriptador = cifrador.encryptor()

    rellenador = padding.PKCS7(algorithms.AES.block_size).padder()
    texto_plano_rellenado = rellenador.update(texto_plano.encode('utf-8')) + rellenador.finalize()

    texto_cifrado = encriptador.update(texto_plano_rellenado) + encriptador.finalize()

    return b64encode(iv + texto_cifrado).decode('utf-8')

def desencriptar_aes256(clave, texto_cifrado):
    clave_bytes = clave.to_bytes(32, byteorder='big')

    texto_cifrado_bytes = b64decode(texto_cifrado.encode('utf-8'))

    iv = texto_cifrado_bytes[:16]

    cifrador = Cipher(algorithms.AES(clave_bytes), modes.CFB(iv), backend=default_backend())

    desencriptador = cifrador.decryptor()

    desencriptado_rellenado = desencriptador.update(texto_cifrado_bytes[16:]) + desencriptador.finalize()

    desrellenador = padding.PKCS7(algorithms.AES.block_size).unpadder()
    desencriptado = desrellenador.update(desencriptado_rellenado) + desrellenador.finalize()

    return desencriptado.decode('utf-8')

def invertir_texto(texto):
    return texto[::-1]

def calcular_md5(archivo):
    hash_md5 = hashlib.md5()
    with open(archivo, "rb") as file:
        for bloque in iter(lambda: file.read(4096), b""):
            hash_md5.update(bloque)
    return hash_md5.hexdigest()

def main():
    host = '127.0.0.1'
    port = 12345
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    numero_e = int(s.recv(1024).decode())
    print("El numero e de RSA:", numero_e)

    mensaje = "llamada a ana"
    enc = cifrar_rot_n(mensaje,numero_e)
    print("Mensaje encriptado:", enc)

    with open("mensajedeentrada.txt", "w") as file:
        file.write(enc)
    
    mensaje_recibido = (s.recv(1024))

    recibido_enjson = mensaje_recibido.decode('utf-8')

    publicas = json.loads(recibido_enjson)

    numero_p, numero_g, calcular_A = publicas

    print("Número p recibido:", numero_p)
    print("Número g recibido:", numero_g)
    print("Número A recibido:", calcular_A)

    numero_b = escoger_b(numero_p)
    print("El numero b esta registrado")

    calcular_B = diffie_hellamn(numero_g,numero_b,numero_p)
    print("El numero B es:", calcular_B)

    s.send(str(calcular_B).encode())

    clave_dif = diffie_hellamn(calcular_A,numero_b,numero_p)
    print("La clave de Diffie Helman es:", clave_dif)

    time.sleep(2)

    with open("archivodesalida.txt", "r") as file:
        aes = file.read()
    print("El mensaje crifrado con AES265 y la clave de Diffie Helman es:", aes)

    des_aes = desencriptar_aes256(clave_dif,aes)
    print("El mensaje descencriptado es:", des_aes)

    vuelta = invertir_texto(des_aes)
    print("El mensaje invertido es:", vuelta)

    with open("mensajedevuelta.txt", "w") as file:
        file.write(vuelta)

    md5_mensaje_de_entrada = calcular_md5("mensajedeentrada.txt")
    print("MD5 del mensaje de entrada:", md5_mensaje_de_entrada)

    md5_mensaje_devuelta = calcular_md5("mensajedevuelta.txt")
    print("MD5 del mensaje devuelta:", md5_mensaje_devuelta)

    s.close()

main()
