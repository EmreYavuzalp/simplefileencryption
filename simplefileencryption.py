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

def set_textenSimetrik(text):
    e3.delete(0, END)
    e3.insert(0, text)
    return

def set_textdeSimetrik(text):
    e3.insert(0, text)
    return

def asimetrikRSAanahtarOlustur():
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

def asimetrikRSAsifrele():
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

def asimetrikRSAsifreCoz():
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


def simetrikSHA256anahtarOlustur():
    password_provided = "password"
    password = password_provided.encode()
    b = int(e3.get())
    a = (os.urandom(b))
    print(a)
    salt = a
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    file = open('key.key', 'wb')
    key = base64.urlsafe_b64encode(kdf.derive(password))
    file.write(key)
    file.close()

def simetrikSHA256Sifrele():
    dosya = filedialog.askopenfile(parent=master, mode='rb', title='Choose a file')
    if dosya:  # file seçilmişse
        data = dosya.read()
        dosya.close()
        a = os.path.basename(dosya.name)
        ##buraya kadar dosyayı seçme işlemleri.
        print(dosya.name)
        print(a)
    file = open('key.key', 'rb')
    key = file.read()
    file.close()
    print("Şifrelenecek dosya ismi: %s" % (a))

    str1 = str(a)
    print(str1)
    str2 = '.en'
    str3 = str1 + str2
    #bu üstteki 3 satır da kritik olmayan kodlar.
    print("Şifrelenmiş dosya ismi %s olacaktır" % (str3))

    # şifrelenecek dosyayı aç
    with open(dosya.name, 'rb') as f:
        data = f.read()

    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    dosya_uzantisi = os.path.splitext(a)
    print(dosya_uzantisi[0])
    b = dosya_uzantisi[0] + "şifrelenmiş" + dosya_uzantisi[1]
    with open(b, 'wb') as f:
        f.write(encrypted)
        #bu kod kısmen önemsiz. İhmal edilebilir.
        set_textenSimetrik(b)
        # Burada, bu alana, test.txt.en yazdırması gerekir.

def simetrikSHA256sifreCoz():
    dosya = filedialog.askopenfile(parent=master, mode='rb', title='Choose a file')
    if dosya:  # file seçilmişse
        data = dosya.read()
        dosya.close()
        a = os.path.basename(dosya.name)
        print(a + " dosyasının şifresi çözülecektir")

    file = open('key.key', 'rb')
    key = file.read()
    file.close()
    str1 = a
    str4 = '.de'
    str5 = str1 + str4
    # şifrelenecek dosyayı aç
    with open(dosya.name, 'rb') as f:
        data = f.read()

    fernet = Fernet(key)
    encrypted = fernet.decrypt(data)

    # Write the encrypted file
    dosya_uzantisi = os.path.splitext(a)
    print(dosya_uzantisi[0])
    b = dosya_uzantisi[0] + "kırılmış" + dosya_uzantisi[1]
    set_textenSimetrik(b)
    with open(b, 'wb') as f:
        f.write(encrypted)




master = tk.Tk()
master.maxsize(3000, 3000)
tk.Label(master,
         text="Asimetrik RSA anahtar boyutu").grid(row=5, column=0)
tk.Label(master,
         text="Yeni dosya ismi").grid(row=6,column=0)
# tk.Text(master, "Burası bir text alanıdıııııııııııııııııııır"),

e1 = tk.Entry(master, width=10)
e2 = tk.Entry(master, width=10)
e3 = tk.Entry(master,width=10)
e4 = tk.Entry(master,width=10)

e1.grid(row=5, column=1)
e2.grid(row=6, column=1)
e3.grid(row=5, column=74)
e4.grid(row=6, column=74)

tk.Label(master,
         text="Burası asimetrik şifreleme alanı").grid(row=0, column=0)

tk.Button(master,
          text='Asimetrik RSA Key oluştur',
          command=asimetrikRSAanahtarOlustur).grid(row=5,
                                       column=2,
                                       sticky=tk.W,
                                       pady=4)
tk.Button(master,
          text='Şifrele:dosya seç', command=asimetrikRSAsifrele).grid(row=8,
                                                          column=1,
                                                          sticky=tk.W,
                                                          pady=4)
tk.Button(master,
          text='Şifre çöz:dosya seç', command=asimetrikRSAsifreCoz).grid(row=8,
                                                     column=2,
                                                     sticky=tk.W,
                                                     pady=4,)
tk.Label(master,
         text="Burası simetrik şifreleme alanı").grid(row=0, column=74)

tk.Button(master,
          text='Simetrik Key oluştur',
          command=simetrikSHA256anahtarOlustur).grid(row=5,
                                       column=75,

                                       pady=4)
tk.Button(master,
          text='Şifrele:dosya seç', command=simetrikSHA256Sifrele).grid(row=8,
                                                    column=74,

                                                    pady=4)
tk.Button(master,
          text='Şifre çöz:dosya seç', command=simetrikSHA256sifreCoz).grid(row=8,
                                                     column=75,

                                                     pady=4,)



tk.Label(master,
         text="Simetrik Anahtar boyutu").grid(row=5, column=73)
tk.Label(master,
         text="Yeni dosyanın ismi").grid(row=6,column=73)






tk.mainloop()
