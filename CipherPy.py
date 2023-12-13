import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes



from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def crear_certificado():
    # Solicitar al usuario que elija el sistema criptográfico
    print("Elige un sistema criptográfico: ")
    print("1. RSA")
    print("2. ECC (Elliptic Curve Cryptography)")
    opcion = input("Selecciona 1 o 2: ")

    if opcion == "1":
        def generate_key_pair(password):
        # Generar par de claves RSA de 2048 bits
            key = RSA.generate(2048)

            # Guardar la clave privada cifrada con una contraseña
            private_key = key.export_key(passphrase=password, pkcs=8, protection="scryptAndAES128-CBC")

            # Guardar la clave pública
            public_key = key.publickey().export_key()

            with open("private_key.pem", "wb") as private_key_file:
                private_key_file.write(private_key)

            with open("public_key.pem", "wb") as public_key_file:
                public_key_file.write(public_key)

            print("Claves generadas y guardadas correctamente.")
        contra= input("Introduce la contrase;a: ")
        generate_key_pair(contra)

    elif opcion == "2":
        def generar_claves():
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            public_key = private_key.public_key()

            with open('private_keyECC.pem', 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            with open('public_keyECC.pem', 'wb') as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
        generar_claves()
        

    else:
        print("Opción no válida.")
        return

    # Generar contraseña para cifrar la llave privada


def iniciar_sesion():
    contra= input("Introduce la contrasena: ")

    try:
        while True:
            print("1. Cifrar mensaje")
            print("2. Descifrar mensaje")
            print("3. Salir")
            opcion = input("Selecciona una opción: ")

            if opcion == "1":
                keyword = "ECC"
                files_in_directory = os.listdir('.')
                files_with_keyword = [file for file in files_in_directory if keyword in file]
                if files_with_keyword:
                    def realizar_intercambio_claves(clave_privada, clave_publica):
                        with open(clave_privada, 'rb') as f:
                            private_key = serialization.load_pem_private_key(
                                f.read(),
                                password=None,
                                backend=default_backend()
                            )

                        with open(clave_publica, 'rb') as f:
                            public_key = serialization.load_pem_public_key(
                                f.read(),
                                backend=default_backend()
                            )

                        shared_key = private_key.exchange(ec.ECDH(), public_key)

                        # Derivamos una clave compartida usando HKDF
                        derived_key = HKDF(
                            algorithm=hashes.SHA256(),
                            length=32,  # Longitud de la clave en bytes
                            salt=None,
                            info=b'',
                            backend=default_backend()
                        ).derive(shared_key)
                        return derived_key
                    
                    def encriptar(texto_plano, clave_compartida, archivo_salida):
                        iv = os.urandom(16)
                        cipher = Cipher(algorithms.AES(clave_compartida), modes.CFB(iv), backend=default_backend())
                        encryptor = cipher.encryptor()
                        ciphertext = encryptor.update(texto_plano.encode()) + encryptor.finalize()

                        with open(archivo_salida, 'wb') as f:
                            f.write(iv + ciphertext)
                    texto_original = input("Introduce el mensaje: ")
                    clave_compartida = realizar_intercambio_claves('private_keyECC.pem', 'public_keyECC.pem')
                    narce= input("introduce el nombre del archivo a crear (.bin): ")
                    encriptar(texto_original, clave_compartida, narce)
                
                else:
                    def encrypt_with_public_key(message, public_key_path, output_file_path):
                        # Cargar la clave pública
                        with open(public_key_path, "rb") as public_key_file:
                            public_key = RSA.import_key(public_key_file.read())

                        # Cifrar el mensaje con la clave pública
                        cipher = PKCS1_OAEP.new(public_key)
                        ciphertext = cipher.encrypt(message.encode("utf-8"))

                        # Guardar el mensaje cifrado en un archivo
                        with open(output_file_path, "wb") as output_file:
                            output_file.write(ciphertext)

                        print("Mensaje cifrado y guardado en", output_file_path)

                    msgwe= input("Introduce el mensaje para descifrar: ")
                    nda= input("Nombre del archivo a generar: ")
                    encrypt_with_public_key(msgwe, "public_key.pem", nda)

            elif opcion == "2":
                keyword = "ECC"
                files_in_directory = os.listdir('.')
                files_with_keyword = [file for file in files_in_directory if keyword in file]
                if files_with_keyword:
                    def realizar_intercambio_claves(clave_privada, clave_publica):
                        with open(clave_privada, 'rb') as f:
                            private_key = serialization.load_pem_private_key(
                                f.read(),
                                password=None,
                                backend=default_backend()
                            )

                        with open(clave_publica, 'rb') as f:
                            public_key = serialization.load_pem_public_key(
                                f.read(),
                                backend=default_backend()
                            )

                        shared_key = private_key.exchange(ec.ECDH(), public_key)

                        # Derivamos una clave compartida usando HKDF
                        derived_key = HKDF(
                            algorithm=hashes.SHA256(),
                            length=32,  # Longitud de la clave en bytes
                            salt=None,
                            info=b'',
                            backend=default_backend()
                        ).derive(shared_key)
                        return derived_key
                    
                    def desencriptar(archivo_cifrado, clave_compartida):
                        with open(archivo_cifrado, 'rb') as f:
                            iv = f.read(16)
                            ciphertext = f.read()

                        cipher = Cipher(algorithms.AES(clave_compartida), modes.CFB(iv), backend=default_backend())
                        decryptor = cipher.decryptor()
                        texto_plano = decryptor.update(ciphertext) + decryptor.finalize()

                        return texto_plano.decode('utf-8')
                   
                    clave_compartida = realizar_intercambio_claves('private_keyECC.pem', 'public_keyECC.pem')
                    narc= input("introduce el nombre del archivo a crear (.bin): ")
                    texto_desencriptado = desencriptar(narc, clave_compartida)
                    print("Texto desencriptado:", texto_desencriptado)

                else:
                    def decrypt_with_private_key(ciphertext_file_path, private_key_path, passphrase):
                        # Cargar la clave privada cifrada con la contraseña
                        with open(private_key_path, "rb") as private_key_file:
                            private_key = RSA.import_key(private_key_file.read(), passphrase=passphrase)

                        # Cargar el mensaje cifrado desde un archivo
                        with open(ciphertext_file_path, "rb") as ciphertext_file:
                            ciphertext = ciphertext_file.read()

                        # Descifrar el mensaje con la clave privada
                        cipher = PKCS1_OAEP.new(private_key)
                        message = cipher.decrypt(ciphertext).decode("utf-8")
                            
                        
                        return message
                    
                    ndad= input("Nombre del archivo a decifrar: ")
                    msgtp= decrypt_with_private_key(ndad, "private_key.pem", contra)
                    print("El mensaje decifrado es: ", msgtp)
                    print(" ")

            elif opcion == "3":
                break
            else:
                print("Opción no válida.")

    except Exception as e:
        print("Error al iniciar sesión:", str(e))

def main():
    print("Bienvenido a la aplicación de gestión de certificados.")
    opcion = input("¿Deseas registrarte (R) o iniciar sesión (I)? ").strip().lower()

    if opcion == "r":
        carpetanombre = input("Introduce tu nombre de usuario: ")
        if not os.path.exists(carpetanombre):
            os.makedirs(carpetanombre)
            os.chdir(carpetanombre)
            crear_certificado()
            os.chdir('..')
        else:
            print("El usuario ya esta registrado. ")
    elif opcion == "i":
        carpetanombre = input("Introduce tu nombre de usuario: ")
        os.chdir(carpetanombre)
        iniciar_sesion()
        os.chdir('..')
    else:
        print("Opción no válida.")

if __name__ == "__main__":
    main()
