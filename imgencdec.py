import tkinter as tk
from tkinter import filedialog
from PIL import Image, ImageTk
from Crypto.Cipher import Blowfish, PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify , unhexlify
from PIL import Image
import matplotlib.pyplot as plt
import numpy as np
import io
from tkinter import messagebox

class App:
    def __init__(self,master):
        self.master = master 
        self.master.title("Image Encryption and Decryption")
        
        # set the window size and center the window
        self.window_width = 700
        self.window_height = 500
        self.screen_width = self.master.winfo_screenwidth()
        self.screen_height = self.master.winfo_screenheight()
        self.x = (self.screen_width / 2) - (self.window_width / 2)
        self.y = (self.screen_height / 2) - (self.window_height / 2)
        self.master.geometry("%dx%d+%d+%d" % (self.window_width, self.window_height, self.x, self.y))

        # create a frame to hold the canvas and buttons
        self.frame = tk.Frame(master)
        self.frame.pack(side="bottom", fill="x")

        # create a canvas to hold the background image
        self.canvas = tk.Canvas(self.frame, width=self.window_width, height=self.window_height - 50)
        self.canvas.pack()
        
        # load the background image and set it as the canvas background
        self.background_image = ImageTk.PhotoImage(Image.open("encrypt_everything_banner.jpg").resize((self.window_width, self.window_height)))
        self.canvas.create_image(0, 0, anchor=tk.NW, image=self.background_image)

        # create a button to open the encryption window
        self.encryption_btn = tk.Button(self.frame, text="Encryption", font=("Arial", 16), bg="#4CAF50", fg="white", command=self.open_encryption_window)
        self.encryption_btn.pack(side="left", padx=20, pady=10)
        
        # create a button to open the decryption window
        self.decryption_btn = tk.Button(self.frame, text="Decryption", font=("Arial", 16), bg="#4CAF50", fg="white", command=self.open_decryption_window)
        self.decryption_btn.pack(side="right", padx=20, pady=10)
    
    def open_encryption_window(self):
        # create a new window for image encryption
        encryption_window = tk.Toplevel(self.master)
        encryption_window.title("Image Encryption")
        
       # create a label to show the selected image file
        self.encryption_filename_label = tk.Label(encryption_window, text="", font=("Arial", 14))
        self.encryption_filename_label.pack()

        # create a button to browse for an image file to encrypt
        self.encryption_browse_btn = tk.Button(encryption_window, text="Browse", font=("Arial", 14), bg="#4CAF50", fg="white", command=self.browse_encryption_file)
        self.encryption_browse_btn.pack(pady=10)

        # create a button to encrypt the image
        self.encryption_encrypt_btn = tk.Button(encryption_window, text="Encrypt", font=("Arial", 14), bg="#2196F3", fg="white", command=self.encrypt_image)
        self.encryption_encrypt_btn.pack(pady=10)

        # create a button to save the encrypted image
        self.encryption_save_btn = tk.Button(encryption_window, text="Save", font=("Arial", 14), bg="#4CAF50", fg="white", command=self.save_encryption_file)
        self.encryption_save_btn.pack(pady=10)

        # initialize variables for storing the file path and the encrypted data
        self.encryption_file_path = None
        self.encryption_data = None
        
    def browse_encryption_file(self):
        # browse for an image file to encrypt
        self.encryption_file_path = filedialog.askopenfilename(initialdir="/", title="Select file", filetypes=(("JPEG files", ".jpg"), ("PNG files", ".png"), ("All files", ".")))
        
        # update the label to show the selected image file
        self.encryption_filename_label.config(text=self.encryption_file_path)
    def encrypt_image(self):
        # check if an image file has been selected for encryption
        if not self.encryption_file_path:
            messagebox.showerror("Error", "Please select an image file to encrypt.")
            return
        
        # read the image file
        with open(self.encryption_file_path, "rb") as f:
            plaintext = f.read()
        
        # perform encryption
        from encryption_file import keys_iv
        
        # Blowfish Layer 1
        blowfish_key = unhexlify(keys_iv['blowfish_key'])
        blowfish_iv = unhexlify(keys_iv['blowfish_iv'])
        blowfish_cipher = Blowfish.new(blowfish_key, Blowfish.MODE_CBC, iv=blowfish_iv)
        blowfish_ciphertext = blowfish_cipher.encrypt(pad(plaintext, Blowfish.block_size))

        # RSA Layer 2
        rsa_n = int(keys_iv['rsa_n'])
        rsa_e = int(keys_iv['rsa_e'])
        rsa_d = int(keys_iv['rsa_d'])
        rsa_key = RSA.construct((rsa_n, rsa_e, rsa_d))
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        rsa_plaintext = blowfish_ciphertext
        rsa_ciphertext = bytearray()
        for i in range(0, len(rsa_plaintext), 190):
            rsa_ciphertext.extend(cipher_rsa.encrypt(rsa_plaintext[i:i+190]))

        # AES Layer 3
        aes_key = unhexlify(keys_iv['aes_key'])
        aes_iv = unhexlify(keys_iv['aes_iv'])
        aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
        aes_ciphertext = aes_cipher.encrypt(pad(rsa_ciphertext, AES.block_size))
        
        # save the encrypted image
        output_image = Image.new("RGBA", self.input_image.size)
        output_image.putdata(list(zip(aes_ciphertext)))
        output_image.save("encrypted_image.png")
        
        # show success message
        messagebox.showinfo("Success", "Image encryption complete. Encrypted image saved as encrypted_image.png.")
    def save_encryption_file(self):
        # save the encrypted image
        # check if the encryption file has been selected
        if not self.encryption_file_path:
            messagebox.showerror("Error", "No file selected for encryption")
            return
        
        # encrypt the selected image file
        ciphertext = self.encrypt_image()
        
        # prompt user to select a location to save the encrypted image file
        file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", ".png")])
        
        # save the encrypted image file
        with open(file_path, "wb") as file:
            file.write(ciphertext)
        
        # show success message
        messagebox.showinfo("Success", "Image encrypted and saved successfully!")
    def open_decryption_window(self):
        # create a new window for image decryption
        decryption_window = tk.Toplevel(self.master)
        decryption_window.title("Image Decryption")
        
        # create a label to show the selected image file
        self.decryption_filename_label = tk.Label(decryption_window, text="", font=("Arial", 14))
        self.decryption_filename_label.pack()
        
        # create a button to browse for an image file to decrypt
        self.decryption_browse_btn = tk.Button(decryption_window, text="Browse", font=("Arial", 14), bg="#4CAF50", fg="white", command=self.browse_decryption_file)
        self.decryption_browse_btn.pack(pady=10)
        
        # create a button to save the decrypted image
        self.decryption_save_btn = tk.Button(decryption_window, text="Save", font=("Arial", 14), bg="#4CAF50", fg="white", command=self.save_decryption_file)
        self.decryption_save_btn.pack(pady=10)
    
    def browse_decryption_file(self):
        # browse for an image file to decrypt
        self.decryption_file_path = filedialog.askopenfilename(initialdir="/", title="Select file", filetypes=(("Encrypted Image files", ".enc"), ("All files", ".*")))
        
        # update the label to show the selected image file
        self.decryption_filename_label.config(text=self.decryption_file_path)
    
    def save_decryption_file(self):
        # save the decrypted image
        pass

root = tk.Tk()
app = App(root)
root.mainloop()