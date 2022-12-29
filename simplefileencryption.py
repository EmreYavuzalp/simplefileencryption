import rsa
from fernet import Fernet
import string
import tkinter as tk
import tkinter.messagebox
import base64
import os
from tkinter import filedialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from tkinter import *
import tkinter.filedialog

def anahtarOlustur():
    key = Fernet.generate_key()
    # ◘write the simetrik key to a file
    k = open('symmetric.key', 'wb')
    k.write(key)
    k.close()
    # private ve public key oluştur
    # burda new keys de bir e.get şeysi yap.
    b = int(e1.get())
    (pubkey, privkey) = rsa.newkeys(b)
    print("%s boyutlu bir anahtar oluşturulacaktır" % b)
    # bu sayiyi değiştirerek yapabiliriz sanki gibi.
    # public keyi dosyaya yazma
    pukey = open('publickey.key', 'wb')
    pukey.write(pubkey.save_pkcs1('PEM'))
    pukey.close()

    # özel keyi dosyaya yazma
    prkey = open('privkey.key', 'wb')
    prkey.write(privkey.save_pkcs1('PEM'))
    prkey.close()
    print(privkey)
    print(pubkey)
    message = b'ornekolsundiyeyazdim'

    crypto = rsa.encrypt(message, pubkey)
    print(crypto)
    decrypt = rsa.decrypt(crypto, privkey)

    print(decrypt.decode())


def sifrele():
    dosya = filedialog.askopenfile(parent=master, mode='rb', title='Şifrelenecek dosyayı seçiniz')
    if dosya:  # file seçilmişse
        data = dosya.read()
        dosya.close()
        a = os.path.basename(dosya.name)
        ##buraya kadar dosyayı seçme işlemleri.
        print(dosya.name)
        #mesela C:/Users/Emre/PycharmProjects/pythonProject/testvideo.mkv dır bu.
        print(a)
        #bu ise testvideo.mkv dir.
        # unpacking the tuple

        # simetrik key dosyasını aç
        skey = open('symmetric.key', 'rb')
        key = skey.read()

        print("Şifrelenecek dosya ismi: %s" % (a))

        # cipher oluştur
        cipher = Fernet(key)


    # print("Şifrelenmiş dosya ismi %s olacaktır" % (str3))

    # open file for şifreleme
    myfile = open(dosya.name, 'rb')
    myfiledata = myfile.read()
    # veriyi şifrele
    encrypted_data = cipher.encrypt(myfiledata)


    dosya_uzantisi = os.path.splitext(a)
    print(dosya_uzantisi[0])
    b = dosya_uzantisi[0]+"şifrelenmiş"+dosya_uzantisi[1]
    print(b)
    edata = open(b, 'wb')
    edata.write(encrypted_data)



    # open the public key file
    pkey = open('publickey.key', 'rb')
    pkdata = pkey.read()

    # load the file
    pubkey = rsa.PublicKey.load_pkcs1(pkdata)

    # encrpy the simetrik key file with the public key
    encrypted_key = rsa.encrypt(key, pubkey)

    # write the encrypted simetrik key to a file
    ekey = open('encrypted_key', 'wb')
    ekey.write(encrypted_key)




def sifreCoz():
    dosya = filedialog.askopenfile(parent=master, mode='rb', title='Choose a file')
    if dosya:  # file seçilmişse
        data = dosya.read()
        dosya.close()
        a = os.path.basename(dosya.name)
        print(a + " dosyasının şifresi çözülecektir")

    prkey = open('privkey.key', 'rb')
    pkey = prkey.read()
    private_key = rsa.PrivateKey.load_pkcs1(pkey)



    e = open('encrypted_key', 'rb')
    ekey = e.read()

    dpubkey = rsa.decrypt(ekey, private_key)

    cipher = Fernet(dpubkey)

    encrypted_data = open(dosya.name, 'rb')
    edata = encrypted_data.read()
    decrypted_data = cipher.decrypt(edata)

    dosya_uzantisi = os.path.splitext(a)
    print(dosya_uzantisi[0])
    b = dosya_uzantisi[0] + "kırılmış" + dosya_uzantisi[1]
    edata = open(b, 'wb')
    edata.write(decrypted_data)
    #print(decrypted_data.decode())


master = tk.Tk()
master.maxsize(1000, 1000)
tk.Label(master,
         text="Anahtar boyutu").grid(row=5, column=0)
tk.Label(master,
         text="Yeni dosya ismi").grid(row=6,column=0)
# tk.Text(master, "Burası bir text alanıdıııııııııııııııııııır"),

e1 = tk.Entry(master, width=10)
e2 = tk.Entry(master, width=10)

e1.grid(row=5, column=1)
e2.grid(row=6, column=1)

tk.Button(master,
          text='Key oluştur',
          command=anahtarOlustur).grid(row=5,
                                       column=2,
                                       sticky=tk.W,
                                       pady=4)
tk.Button(master,
          text='Şifrele:dosya seç', command=sifrele).grid(row=8,
                                                          column=1,
                                                          sticky=tk.W,
                                                          pady=4)
tk.Button(master,
          text='Şifre çöz:dosya seç', command=sifreCoz).grid(row=8,
                                                     column=2,
                                                     sticky=tk.W,
                                                     pady=4,)
tk.mainloop()
