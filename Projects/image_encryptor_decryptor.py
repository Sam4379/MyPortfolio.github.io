from tkinter import Tk, Button, Label, Entry, filedialog,messagebox
from Crypto.Cipher import DES3
from hashlib import md5

class ImageEncryptorDecryptor:
    def __init__(self, master):
        self.master = master
        self.master.title("Image Encryptor/Decryptor")

        self.operation_choice = None
        self.file_path = None
        self.key = None

        self.create_widgets()

    def create_widgets(self):
        # Operation choice
        self.operation_label = Label(self.master, text="Choose operation:")
        self.operation_label.grid(row=0, column=0, sticky="w")

        self.operation_button_encrypt = Button(self.master, text="Encryption", command=self.choose_encryption)
        self.operation_button_encrypt.grid(row=0, column=1, padx=10, pady=5)

        self.operation_button_decrypt = Button(self.master, text="Decryption", command=self.choose_decryption)
        self.operation_button_decrypt.grid(row=0, column=2, padx=10, pady=5)

        # File selection
        self.file_label = Label(self.master, text="File path:")
        self.file_label.grid(row=1, column=0, sticky="w")

        self.file_entry = Entry(self.master, width=40)
        self.file_entry.grid(row=1, column=1, padx=10, pady=5)

        self.file_button = Button(self.master, text="Browse", command=self.browse_file)
        self.file_button.grid(row=1, column=2, padx=5)

        # Key entry
        self.key_label = Label(self.master, text="TDES key:")
        self.key_label.grid(row=2, column=0, sticky="w")

        self.key_entry = Entry(self.master, width=40, show='*')
        self.key_entry.grid(row=2, column=1, padx=10, pady=5)

        # Process button
        self.process_button = Button(self.master, text="Process", command=self.process_operation)
        self.process_button.grid(row=3, column=1, pady=10)

    def choose_encryption(self):
        self.operation_choice = '1'

    def choose_decryption(self):
        self.operation_choice = '2'

    def browse_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        if self.file_path:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, self.file_path)

    def process_operation(self):
        self.key = self.key_entry.get()
        if self.operation_choice and self.file_path and self.key:
            try:
                key_hash = md5(self.key.encode('ascii')).digest()
                tdes_key = DES3.adjust_key_parity(key_hash)
                cipher = DES3.new(tdes_key, DES3.MODE_EAX, nonce=b'0')

                with open(self.file_path, 'rb') as input_file:
                    file_bytes = input_file.read()

                    if self.operation_choice == '1':
                        new_file_bytes = cipher.encrypt(file_bytes)
                    else:
                        new_file_bytes = cipher.decrypt(file_bytes)

                with open(self.file_path, 'wb') as output_file:
                    output_file.write(new_file_bytes)

                self.show_message("Success", "Operation completed successfully!")
            except Exception as e:
                self.show_message("Error", f"An error occurred: {str(e)}")
        else:
            self.show_message("Warning", "Please select operation, file, and enter a key.")

    def show_message(self, title, message):
        messagebox.showinfo(title, message)

if __name__ == "__main__":
    root = Tk()
    app = ImageEncryptorDecryptor(root)
    root.mainloop()
