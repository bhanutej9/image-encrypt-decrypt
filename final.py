#!/usr/bin/env python

from __future__ import division, print_function, unicode_literals
import sys
import random
import argparse
import logging
from tkinter import *
from tkinter import filedialog, messagebox
import os
from PIL import Image
import math
from Crypto.Cipher import AES
import hashlib
import binascii
import numpy as np

global password 

def load_image(name):
    return Image.open(name)

def prepare_message_image(image, size):
    if size != image.size:
        image = image.resize(size, Image.LANCZOS)
    return image

def generate_secret(size):
    width, height = size
    new_secret_image = Image.new(mode="RGB", size=(width * 2, height * 2))
    for x in range(0, 2 * width, 2):
        for y in range(0, 2 * height, 2):
            color1, color2, color3 = np.random.randint(255, size=3)
            new_secret_image.putpixel((x, y), (color1, color2, color3))
            new_secret_image.putpixel((x+1, y), (255-color1, 255-color2, 255-color3))
            new_secret_image.putpixel((x, y+1), (255-color1, 255-color2, 255-color3))
            new_secret_image.putpixel((x+1, y+1), (color1, color2, color3))
    return new_secret_image

def generate_image_back(secret_image, ciphered_image):
    width, height = secret_image.size
    new_image = Image.new(mode="RGB", size=(int(width / 2), int(height / 2)))
    for x in range(0, width, 2):
        for y in range(0, height, 2):
            sec = secret_image.getpixel((x, y))
            cip = ciphered_image.getpixel((x, y))
            color1 = (cip[0] - sec[0]) % 256
            color2 = (cip[1] - sec[1]) % 256
            color3 = (cip[2] - sec[2]) % 256
            new_image.putpixel((int(x/2), int(y/2)), (color1, color2, color3))
    return new_image

def encrypt(imagename, password):
    obj = AES.new(password, AES.MODE_CBC, b'This is an IV456')
    with open(imagename, 'rb') as f:
        plaintext = f.read()
    while len(plaintext) % 16 != 0:
        plaintext += b' '
    ciphertext = obj.encrypt(plaintext)
    with open(imagename + ".crypt", 'wb') as f:
        f.write(ciphertext)
    messagebox.showinfo("Success", "Encryption Completed!")

def decrypt(ciphername, password):
    obj2 = AES.new(password, AES.MODE_CBC, b'This is an IV456')
    with open(ciphername, 'rb') as f:
        ciphertext = f.read()
    plaintext = obj2.decrypt(ciphertext).rstrip(b' ')
    decrypted_filename = os.path.join(file_path_d, "decrypted_" + os.path.basename(ciphername).replace(".crypt", ""))
    with open(decrypted_filename, 'wb') as f:
        f.write(plaintext)
    messagebox.showinfo("Success", "Decryption Completed!")

def image_open():
    global file_path_e
    enc_pass = passg.get()
    if not enc_pass:
        messagebox.showinfo("Password Alert", "Please enter a password.")
    else:
        password = hashlib.sha256(enc_pass.encode()).digest()
        filename = filedialog.askopenfilename()
        file_path_e = os.path.dirname(filename)
        encrypt(filename, password)
        passg.delete(0, END)  # Clear password field after encryption

def cipher_open():
    global file_path_d
    dec_pass = passg.get()
    if not dec_pass:
        messagebox.showinfo("Password Alert", "Please enter a password.")
    else:
        password = hashlib.sha256(dec_pass.encode()).digest()
        filename = filedialog.askopenfilename()
        file_path_d = os.path.dirname(filename)
        decrypt(filename, password)
        passg.delete(0, END)  # Clear password field after decryption

class App:
    def __init__(self, master):
        global passg
        master.title("Image Encryption")
        Label(master, text="Enter Encrypt/Decrypt Password:").pack()
        passg = Entry(master, show="*", width=20)
        passg.pack()
        Button(master, text="Encrypt", command=image_open, width=25, height=5).pack(side=LEFT)
        Button(master, text="Decrypt", command=cipher_open, width=25, height=5).pack(side=RIGHT)

root = Tk()
app = App(root)
root.mainloop()
