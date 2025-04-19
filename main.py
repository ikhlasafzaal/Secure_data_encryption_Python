import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet

# ----- Utility Functions -----
DATA_FILE = "data.json"  # Data ko store karne ki file
KEY_FILE = "key.key"  # Encryption key ko store karne ki file

# Load ya create encryption key
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        # Agar key already hai, toh load kar lo
        with open(KEY_FILE, "rb") as f:
            return f.read()
    # Agar key nahi hai, toh new key generate karte hain
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

# Load ya initialize user data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)  # File se data load kar lo
    return {}

# Data ko JSON file mein save karo
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# Passkey ko hash karne ka function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# ----- Initialization -----
cipher = Fernet(load_or_create_key())  # Fernet cipher initialize karte hain
stored_data = load_data()  # Pura data load kar lo

# Session state setup
if "username" not in st.session_state:
    st.session_state.username = ""
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = True

# Manual rerun handle karne ka function
if st.session_state.get("rerun_flag"):
    st.session_state["rerun_flag"] = False
    st._set_query_params()
    st.stop()

def fake_rerun():
    st.session_state["rerun_flag"] = True
    st.stop()

# ----- UI -----
st.title("🔐 Secure Data Encryption System")
st.subheader("A Scalable, Secure, and Efficient Solution for Multi-User Data Storage and Retrieval 📦")


# Sidebar menu
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigate Through the System", menu)

# ----- Home Page -----
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Multi-user data encryption with passkey protection and lockout system.")

# ----- Store Data -----
elif choice == "Store Data":
    st.subheader("📥 Store Data Securely")
    username = st.text_input("Username:")  # Username input
    user_data = st.text_area("Enter Text to Encrypt:")  # Data input
    passkey = st.text_input("Set a Passkey:", type="password")  # Passkey input

    # Encrypt & save button
    if st.button("Encrypt & Save"):
        if username and user_data and passkey:
            encrypted_text = cipher.encrypt(user_data.encode()).decode()  # Encrypt the data
            hashed_pass = hash_passkey(passkey)  # Hash the passkey

            # Store under user in data dictionary
            if username not in stored_data:
                stored_data[username] = []
            stored_data[username].append({
                "encrypted_text": encrypted_text,
                "passkey": hashed_pass
            })
            save_data(stored_data)  # Data ko save kar lo
            st.success("✅ Data securely stored.")
            st.code(encrypted_text, language="text")  # Display encrypted text
        else:
            st.error("⚠️ Please fill all fields.")  # Error agar koi field empty ho

# ----- Retrieve Data -----
elif choice == "Retrieve Data":
    st.subheader("🔓 Retrieve Your Data")

    # Lockout check
    if st.session_state.failed_attempts >= 3:
        remaining = int(st.session_state.lockout_time - time.time())  # Time remaining for lockout
        if remaining > 0:
            st.error(f"🚫 Too many failed attempts. Try again in {remaining} seconds.")
            st.stop()  # Stop further actions
        else:
            st.session_state.failed_attempts = 0  # Reset failed attempts
            st.session_state.lockout_time = 0  # Reset lockout time

    # Retrieve inputs
    username = st.text_input("Username:")
    encrypted_text = st.text_area("Paste Encrypted Text:")
    passkey = st.text_input("Enter Passkey:", type="password")

    # Decrypt button
    if st.button("Decrypt"):
        if username and encrypted_text and passkey:
            entries = stored_data.get(username, [])
            hashed_pass = hash_passkey(passkey)  # Hash passkey to compare

            match_found = False  # Flag for successful match

            # Check matching entry
            for item in entries:
                if item["encrypted_text"] == encrypted_text and item["passkey"] == hashed_pass:
                    try:
                        decrypted = cipher.decrypt(encrypted_text.encode()).decode()  # Decrypt data
                        st.success("✅ Decrypted Data:")
                        st.code(decrypted, language="text")  # Display decrypted text
                        st.session_state.failed_attempts = 0  # Reset failed attempts
                        match_found = True
                        break
                    except:
                        pass

            # If no match, increase failed attempts
            if not match_found:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect credentials! Attempts remaining: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + 30  # Lockout for 30 seconds
                    st.warning("🚫 Too many attempts. Locked for 30 seconds.")
                    st.stop()  # Stop further actions
        else:
            st.error("⚠️ All fields are required!")  # Error if any field is empty

# ----- Login (to Reset Lockout) -----
elif choice == "Login":
    st.subheader("🔑 Admin Login (Reset Lockout)")
    admin_pass = st.text_input("Enter Master Password:", type="password")
    if st.button("Login"):
        if admin_pass == "admin123":  # Hardcoded master password for admin
            st.session_state.failed_attempts = 0  # Reset failed attempts
            st.session_state.lockout_time = 0  # Reset lockout time
            st.success("✅ Reauthorized. Lockout cleared.")
            fake_rerun()  # Trigger rerun after successful login
        else:
            st.error("❌ Incorrect master password.")  # Error if password doesn't match
