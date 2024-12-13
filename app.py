import streamlit as st
from aes_code_final import encrypt, decrypt  # Import AES functions from your code file

# App Title
st.title("AES Encryption/Decryption Tool")
st.write("Encrypt or decrypt messages using AES-128 encryption.")

# User Inputs
operation = st.selectbox("Select Operation", ["Encrypt", "Decrypt"])
message = st.text_input("Enter Message (Hexadecimal):", placeholder="e.g., 00112233445566778899aabbccddeeff")
key = st.text_input("Enter Key (Hexadecimal):", placeholder="e.g., 000102030405060708090a0b0c0d0e0f")

# Run the operation
if st.button("Run"):
    try:
        # Convert inputs to bytes
        message_bytes = bytes.fromhex(message)
        key_bytes = bytes.fromhex(key)

        # Perform the selected operation
        if operation == "Encrypt":
            result = encrypt(message_bytes, key_bytes)
        else:
            result = decrypt(message_bytes, key_bytes)
        
        # Display the result
        st.success(f"Result (Hexadecimal): {result.hex()}")
    except ValueError:
        st.error("Invalid input! Ensure your message and key are valid hexadecimal strings.")
    except Exception as e:
        st.error(f"An error occurred: {e}")
