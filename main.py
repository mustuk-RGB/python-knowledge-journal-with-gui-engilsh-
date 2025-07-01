import os
import hashlib
import base64
import requests
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
from datetime import datetime

# --- Constants and Settings ---
# This path is specific to Termux's home directory
BASE_DIR = os.path.join(os.path.expanduser('~'), 'knowledge_pills')
PASSWORD_FILE = os.path.join(BASE_DIR, '.password')
KNOWLEDGE_LOG_FILE = os.path.join(BASE_DIR, 'knowledge_log.dat')

# --- Helper Functions (Same as before, with minor adjustments for GUI) ---
def encrypt(data, key):
    """Encrypts data using simple XOR (for demo purposes)."""
    key_bytes = hashlib.sha256(key.encode()).digest()
    return base64.b64encode(
        bytes(a ^ b for a, b in zip(data.encode(), key_bytes * (len(data) // len(key_bytes) + 1)))
    ).decode()

def decrypt(encrypted_data, key):
    """Decrypts data."""
    key_bytes = hashlib.sha256(key.encode()).digest()
    decoded_data = base64.b64decode(encrypted_data.encode())
    return bytes(a ^ b for a, b in zip(decoded_data, key_bytes * (len(decoded_data) // len(key_bytes) + 1))).decode()

def authenticate_user():
    """Handles password creation and verification for GUI."""
    if not os.path.exists(BASE_DIR):
        os.makedirs(BASE_DIR)

    if os.path.exists(PASSWORD_FILE):
        while True:
            entered_password = simpledialog.askstring("Authentication", "Please enter your password:", show='*')
            if not entered_password: # User clicked cancel
                return None
            
            with open(PASSWORD_FILE, 'r') as f:
                stored_password_hash = f.read()
            
            if hashlib.sha256(entered_password.encode()).hexdigest() == stored_password_hash:
                messagebox.showinfo("Success", "Password correct! Welcome.")
                return entered_password
            else:
                messagebox.showerror("Error", "Incorrect password. Please try again.")
    else:
        while True:
            new_password = simpledialog.askstring("Set Password", "Set a new password:", show='*')
            if not new_password: # User clicked cancel
                return None
            
            confirm_password = simpledialog.askstring("Confirm Password", "Confirm your new password:", show='*')
            if new_password == confirm_password:
                with open(PASSWORD_FILE, 'w') as f:
                    f.write(hashlib.sha256(new_password.encode()).hexdigest())
                messagebox.showinfo("Success", "Password successfully set!")
                return new_password
            else:
                messagebox.showerror("Error", "Passwords do not match. Please try again.")

def fetch_info(topic):
    """Performs a simple web search for the given topic and summarizes."""
    status_label.config(text=f"Searching for '{topic}'...")
    search_query = topic.replace(" ", "+")
    url = f"https://www.google.com/search?q={search_query}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        info_snippets = []
        for tag in soup.find_all(['span', 'div'], class_=lambda x: x and ('st' in x or 'BNeawe' in x or 'ZINbbc' in x)):
            text = tag.get_text(separator=" ", strip=True)
            if 50 < len(text) < 500: # Filter for reasonable length snippets
                info_snippets.append(text)
                if len(info_snippets) >= 3:
                    break
        
        if info_snippets:
            summary = "\n".join(info_snippets[:3])
            status_label.config(text="Information summary successfully retrieved.")
            return summary
        else:
            status_label.config(text="Not enough information found for the topic.")
            return "No information found."
    except requests.exceptions.RequestException as e:
        status_label.config(text=f"Error fetching info from web: {e}")
        return "Connection error or no info found."
    except Exception as e:
        status_label.config(text=f"Unexpected error processing info: {e}")
        return "Processing error."

# --- Tkinter GUI Functions ---
def create_knowledge_pill():
    """Initiates the process of creating a new knowledge pill."""
    topic = simpledialog.askstring("New Knowledge Pill", "What topic would you like to gather information about?")
    if topic:
        info_summary = fetch_info(topic)
        
        if "error" not in info_summary.lower() and "no information" not in info_summary.lower():
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            entry = f"Topic: {topic}\nDate: {timestamp}\nInfo: {info_summary}\n--- END ---\n"
            encrypted_entry = encrypt(entry, global_password)
            
            try:
                with open(KNOWLEDGE_LOG_FILE, 'a') as f:
                    f.write(encrypted_entry + "\n")
                messagebox.showinfo("Success", "Knowledge pill successfully added and encrypted!")
                status_label.config(text="New knowledge pill saved.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save knowledge pill: {e}")
                status_label.config(text="Failed to save knowledge pill.")
        else:
            messagebox.showerror("Error", "Could not create knowledge pill. Please check your connection or try a different topic.")
            status_label.config(text="Knowledge pill creation failed.")

def view_knowledge_history():
    """Displays the history of knowledge pills."""
    display_area.delete(1.0, tk.END) # Clear previous content
    status_label.config(text="Loading knowledge history...")

    if not os.path.exists(KNOWLEDGE_LOG_FILE):
        display_area.insert(tk.END, "No knowledge pills saved yet.\n")
        status_label.config(text="History loaded (empty).")
        return
    
    try:
        with open(KNOWLEDGE_LOG_FILE, 'r') as f:
            all_encrypted_entries = f.read().splitlines()
        
        for encrypted_entry in all_encrypted_entries:
            if encrypted_entry:
                try:
                    decrypted_entry = decrypt(encrypted_entry, global_password)
                    display_area.insert(tk.END, decrypted_entry + "\n\n")
                except Exception as e:
                    display_area.insert(tk.END, f"Failed to decrypt an entry (might be corrupted or wrong password): {e}\n\n")
        status_label.config(text="Knowledge history loaded.")
    except Exception as e:
        messagebox.showerror("Error", f"Error reading knowledge file: {e}")
        status_label.config(text="Error loading history.")

# --- Main GUI Setup ---
def setup_gui():
    global root, display_area, status_label, global_password

    # Authenticate user first
    global_password = authenticate_user()
    if not global_password:
        messagebox.showinfo("Exiting", "Authentication failed or cancelled. Exiting application.")
        return

    root = tk.Tk()
    root.title("✨ Knowledge Pill Journal ✨")
    root.geometry("600x500") # Set initial window size

    # Frame for buttons
    button_frame = tk.Frame(root, padx=10, pady=10)
    button_frame.pack(pady=5)

    create_button = tk.Button(button_frame, text="Create New Knowledge Pill", command=create_knowledge_pill)
    create_button.pack(side=tk.LEFT, padx=5)

    view_button = tk.Button(button_frame, text="View Knowledge History", command=view_knowledge_history)
    view_button.pack(side=tk.LEFT, padx=5)

    exit_button = tk.Button(button_frame, text="Exit", command=root.destroy)
    exit_button.pack(side=tk.LEFT, padx=5)

    # Scrolled text area for displaying knowledge
    display_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=70, height=20, font=("TkDefaultFont", 10))
    display_area.pack(padx=10, pady=5)
    display_area.insert(tk.END, "Welcome to your secret Knowledge Pill Journal!\n")
    display_area.insert(tk.END, "Click 'Create New Knowledge Pill' to start or 'View Knowledge History' to see your saved entries.\n")

    # Status label
    status_label = tk.Label(root, text="Ready.", bd=1, relief=tk.SUNKEN, anchor=tk.W)
    status_label.pack(side=tk.BOTTOM, fill=tk.X)

    root.mainloop()

if __name__ == "__main__":
    setup_gui()

