import streamlit as st
from aes_code_final import encrypt, decrypt  # Import AES functions

# App Title
st.title("AES Encryption/Decryption Tool")
st.write("Encrypt or decrypt messages using AES-128 encryption.")

# Input Type Toggle
input_type = st.radio("Input Type", ["Hexadecimal", "Plain Text"])

# User Inputs
operation = st.selectbox("Select Operation", ["Encrypt", "Decrypt"])

if input_type == "Hexadecimal":
    message = st.text_input("Enter Message (Hexadecimal):", placeholder="e.g., 00112233445566778899aabbccddeeff")
    key = st.text_input("Enter Key (Hexadecimal):", placeholder="e.g., 000102030405060708090a0b0c0d0e0f")
else:
    message = st.text_input("Enter Message (Plain Text):", placeholder="e.g., Hello World")
    key = st.text_input("Enter Key (Plain Text):", placeholder="e.g., MySecretKey123")

# Run the operation
if st.button("Run"):
    try:
        # Handle Hexadecimal Input
        if input_type == "Hexadecimal":
            message_bytes = bytes.fromhex(message)
            key_bytes = bytes.fromhex(key)
        else:  # Handle Plain Text Input
            message_bytes = message.encode("utf-8")  # Convert string to bytes
            key_bytes = key.encode("utf-8")

        # Validate Key Length (AES requires 16, 24, or 32 bytes)
        if len(key_bytes) not in [16, 24, 32]:
            st.error("Invalid key length! Key must be 16, 24, or 32 bytes.")
        else:
            # Perform the selected operation
            if operation == "Encrypt":
                result = encrypt(message_bytes, key_bytes)
            else:
                result = decrypt(message_bytes, key_bytes)

            # Display the result
            st.success(f"Result (Hexadecimal): {result.hex()}")

    except ValueError:
        st.error("Invalid input! Ensure your message and key are valid.")
    except Exception as e:
        st.error(f"An error occurred: {e}")
