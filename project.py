import cv2
import os
import tkinter as tk
from tkinter import simpledialog
from tkinter import filedialog
from PIL import ImageTk, Image  

def generate_lookup_tables():
    encrypt_table = {chr(i): i for i in range(256)}
    decrypt_table = {i: chr(i) for i in range(256)}
    return encrypt_table, decrypt_table

def encrypt_image(img, message):
    n, m, z = 0, 0, 0
    for char in message:
        img[n, m, z] = ord(char)
        n += 1
        m += 1
        z = (z + 1) % 3

def decrypt_message(img):
    n, m, z = 0, 0, 0
    decrypted_message = ""
    for _ in range(len(msg)):
        decrypted_message += chr(img[n, m, z])
        n += 1
        m += 1
        z = (z + 1) % 3
    return decrypted_message

def open_image():
    file_path = tk.filedialog.askopenfilename(title="Select Image File", filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
    
    img = cv2.imread(file_path)
    if img is None:
        tk.messagebox.showerror("Error", "Failed to load the image.")
    return img

def encrypt_and_save():
    global img, msg, encrypt_password_entry
    img = open_image()
    if img is not None:
        msg = msg_entry.get()
        encrypt_image(img, msg)
        cv2.imwrite("encryptedImage.jpg", img)
        tk.messagebox.showinfo("Success", "Image encrypted and saved as encryptedImage.jpg.")
    msg_entry.delete(0, tk.END)  # Clear the message entry

def decrypt_and_display():
    global img, msg, encrypt_password_entry
    decrypt_password = decrypt_password_entry.get()
    if decrypt_password == encrypt_password_entry.get():
        decrypted_msg = decrypt_message(img)
        tk.messagebox.showinfo("Decryption Result", f"Decrypted message: {decrypted_msg}")
    else:
        tk.messagebox.showerror("Error", "Incorrect password.")

# Main GUI window
root = tk.Tk()
root.title("Image Encryption Decryption Application")
root.geometry("900x450")

#Creating Frames
frame1=tk.Frame(root,background='#dba40b')
frame1.pack(side="left",fill="both",expand=True)
frame2=tk.Frame(root,background='#694e05')
frame2.pack(side="right",fill="both",expand=True)

head_label=tk.Label(frame1,text="Encryption",font=('Arial',12))
head_label.pack(pady=30)

head_label2=tk.Label(frame2,text="Decryption",font=('Arial',12))
head_label2.pack(pady=30)

#Show Encrypt Image
img = Image.open("./image.jpeg")
Image1=img.resize((300,205),Image.ANTIALIAS)
EncImage=ImageTk.PhotoImage(Image1)
enc_img_label=tk.Label(frame1,image=EncImage)
enc_img_label.pack()

# Show Decrypt Image
img = Image.open("./encryptedImage.jpg")
Image2=img.resize((300,205),Image.ANTIALIAS)
DecImage=ImageTk.PhotoImage(Image2)
enc_img_label=tk.Label(frame2,image=DecImage)
enc_img_label.pack()

# Text Entry Boxes
msg_label = tk.Label(frame1, text="Enter Secret Message")
msg_label.pack()
msg_entry = tk.Entry(frame1)
msg_entry.pack(pady=5)

encrypt_password_label = tk.Label(frame1, text="Create Password")
encrypt_password_label.pack()
encrypt_password_entry = tk.Entry(frame1, show="*")
encrypt_password_entry.pack(pady=5)

decrypt_password_label = tk.Label(frame2, text="Enter Password")
decrypt_password_label.pack()
decrypt_password_entry = tk.Entry(frame2, show="*")
decrypt_password_entry.pack(pady=5)

# Buttons
encrypt_button = tk.Button(frame1, text="Encrypt Image", command=encrypt_and_save)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(frame2, text="Decrypt Image", command=decrypt_and_display)
decrypt_button.pack(pady=10)

# Run the GUI
root.mainloop()