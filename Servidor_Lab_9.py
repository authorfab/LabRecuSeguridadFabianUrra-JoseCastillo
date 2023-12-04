# Laboratorio 9 Recuperativo Seguridad Informatcia
# Fabian Urra y Jose Castillo

import socket, sys, random, json
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
import os
import hashlib

def es_primo(numero):
    if numero <= 1:
        return False
    if numero <= 3:
        return True
    if numero % 2 == 0 or numero % 3 == 0:
        return False
    i = 5
    while i * i <= numero:
        if numero % i == 0 or numero % (i + 2) == 0:
            return False
        i += 6
    return True

def generar_pq():
    primos = []
    for numero in range(501, 1000):
        if es_primo(numero):
            primos.append(numero)
    
    if primos:
        primo_aleatorio = random.choice(primos)
        return primo_aleatorio
    else:
        return None
    

def calcular_mcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mcd_es_1(num1, num2):
    mcd = calcular_mcd(num1, num2)
    if (mcd == 1):
        return True
    else:
        return False

def escoger_e(num):
    aux = True
    escoger_e = int(input("Ingrese un numero e: "))
    while(aux):
        if escoger_e> 1 and escoger_e <num and mcd_es_1(escoger_e,num) == True and inverso(escoger_e,num) != False:
            print("Numero a cumple las condiciones")
            return escoger_e
        else:
            print("Intentelo nuevamente")
            escoger_e = int(input("Ingrese un numero e: "))

def gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, x, y = gcd(b % a, a)
        return g, y - (b // a) * x, x

def inverso(a, n):
    g, x, y = gcd(a, n)
    if g != 1:
        return False
    else:
        return x % n

def RSA(m,e,n):
    enc = (m**e) % n
    return enc

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

def invertir_texto(texto):
    return texto[::-1]

def generar_g(num):
    g = random.randint(200,num-100)
    return g


def escoger_a(num):
    aux = True
    escoger_a = int(input("Ingrese su numero a que mayor que cero y menor que p: "))
    while(aux):
        if escoger_a> 0 and escoger_a <num:
            print("Numero a cumple las condiciones")
            return escoger_a
        else:
            print("Intentelo nuevamente")
            escoger_a = int(input("Ingrese su numero a mayor que cero y menor que p: "))

def diffie_hellamn(g,a,p):
    A = (g**a) % p
    return A


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
    s.bind((host, port))
    s.listen(1)

    print(f"Esperando conexiones en {host}:{port}...")
    conex, addr = s.accept()
    print(f"Conexión establecida con {addr}")

    numero_p = generar_pq()
    numero_q = generar_pq()
    print("Estos son los numeros p y q de RSA:", numero_p, numero_q)

    numero_phi = (numero_p-1) * (numero_q-1)
    print("Estos es el numero phi de RSA:", numero_phi)

    numero_e = escoger_e(numero_phi)
    print("Este es el numero e escodigo de RSA:", numero_e)

    conex.send(str(numero_e).encode())

    time.sleep(2)

    with open("mensajedeentrada.txt", "r") as file:
        enc = file.read()
    print("El mensaja encriptado es:", enc)
     
    des = descifrar_rot_n(enc,numero_e)
    print("El mensaje desencriptado es:", des)

    guardar = invertir_texto(des)
    print("El mensaje invertido es:", guardar)

    with open("mensajedesalida.txt", "w") as file:
        file.write(guardar)

    numero_p2 = generar_pq()
    print("El numero publico p es:", numero_p2)

    numero_g = generar_g(numero_p2)
    print("El numero publico g es:", numero_g)

    numero_a = escoger_a(numero_p2)
    print("El numero a esta registrado:", numero_a)

    calcular_A = diffie_hellamn(numero_g,numero_a,numero_p2)
    print("El numero A es:", calcular_A)
    
    tupla = (numero_p2,numero_g,calcular_A)
    mensaje = json.dumps(tupla)
    conex.send(mensaje.encode('utf-8'))

    numero_B = int(conex.recv(1024).decode())
    print("Este es el numero B recibido", numero_B)

    clave_dif = diffie_hellamn(numero_B,numero_a,numero_p2)
    clave_dif = int(clave_dif)
    print("Esta es la clave de Diffie Helman", clave_dif)

    aes = encriptar_aes256(clave_dif,des)
    print("El mensaje encriptado con AES256 y la clave Diffie Helman es:", aes)

    with open("archivodesalida.txt", "w") as file:
        file.write(aes)

    
    md5_mensaje_de_salida = calcular_md5("mensajedesalida.txt")
    print("MD5 del mensaje de salida:", md5_mensaje_de_salida)

    md5_archivo_salida = calcular_md5("archivodesalida.txt")
    print("MD5 del archivo de salida:", md5_archivo_salida)

    s.close()

main()