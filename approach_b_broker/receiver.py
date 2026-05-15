import socket
import json
import os
import time
import uuid
import tempfile
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import argparse

# --- Cryptography Utility Functions ---
def decrypt_aes_key_with_rsa(encrypted_aes_key: bytes, private_key_path: str) -> bytes:
    """Decrypts an AES key using RSA private key decryption with OAEP padding."""
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None, # No password for this example
            backend=default_backend()
        )
    decrypted_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

def decrypt_data_aes_gcm(ciphertext: bytes, tag: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypts data using AES-256-GCM with authentication tag verification."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def calculate_sha256(filepath: str) -> bytes:
    """Calculates the SHA-256 hash of a file."""
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(4096) # Read in smaller chunks for hashing
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.finalize()
# ---------------------------------------------------------------------------

# Constants
BROKER_HOST = 'localhost'
BROKER_PORT = 8080
CHUNK_SIZE = 4 * 1024 * 1024 # 4MB
GCM_TAG_SIZE = 16 # AES-GCM tag is 16 bytes

def send_message(sock, message_type, data):
    """Helper to send structured messages (JSON metadata, binary data, or command)"""
    try:
        if message_type == "json":
            payload = json.dumps(data).encode('utf-8')
        elif message_type == "binary":
            payload = data
        elif message_type == "command":
            payload = data.encode('utf-8')
        else:
            raise ValueError("Invalid message_type")

        # Prefix with 4-byte length
        sock.sendall(len(payload).to_bytes(4, 'big'))
        sock.sendall(payload)
    except socket.error as e:
        print(f"Socket error while sending message: {e}")
        raise

def recv_exactly(sock, n):
    """Helper to receive exactly n bytes from a socket."""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def recv_message(sock, message_type):
    """Helper to receive structured messages (JSON metadata or binary data)"""
    try:
        # Read 4-byte length prefix
        len_bytes = recv_exactly(sock, 4)
        if not len_bytes:
            return None # Connection closed
        message_length = int.from_bytes(len_bytes, 'big')

        # Read payload
        payload = recv_exactly(sock, message_length)
        if payload is None:
            raise ConnectionResetError("Socket connection broken during receive.")

        if message_type == "json":
            return json.loads(payload.decode('utf-8'))
        elif message_type == "binary":
            return payload
        else:
            raise ValueError("Invalid message_type")
    except socket.error as e:
        print(f"Socket error while receiving message: {e}")
        raise
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        raise

def receiver_main(file_id: str, output_filename: str, private_key_path: str):
    if not os.path.exists(private_key_path):
        print(f"Error: Private key file '{private_key_path}' not found. Please generate it using generate_keys.py.")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_output_filepath = None # Initialize outside try for finally block access
    try:
        sock.connect((BROKER_HOST, BROKER_PORT))
        print(f"Connected to broker at {BROKER_HOST}:{BROKER_PORT}")

        # Send DOWNLOAD command
        send_message(sock, "command", "DOWNLOAD")

        # Request file from broker
        send_message(sock, "json", {"file_id": file_id})
        print(f"Requested file ID: {file_id} from broker.")

        # Receive metadata from broker
        broker_response = recv_message(sock, "json")
        if broker_response is None:
            print("Broker disconnected during metadata reception.")
            return
        if broker_response.get('status') != 'success':
            print(f"Broker error: {broker_response.get('message', 'Unknown error')}")
            return

        metadata = broker_response['metadata']
        encrypted_aes_key = bytes.fromhex(metadata['encrypted_aes_key'])
        nonce = bytes.fromhex(metadata['nonce'])
        original_hash = bytes.fromhex(metadata['original_hash'])
        ttl_expiry_timestamp = metadata['ttl_expiry_timestamp'] # For receiver to check TTL
        total_original_file_size = metadata['total_original_file_size'] # For receiver to verify final size
        total_encrypted_payload_size = metadata['total_encrypted_payload_size'] # For receiver to know when to stop receiving encrypted chunks

        print("Received metadata from broker.")

        # 1. Check TTL
        if time.time() > ttl_expiry_timestamp:
            raise Exception(f"File {file_id} has expired (TTL exceeded).")

        # 2. Decrypt AES key with RSA private key
        aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key_path)
        print("Decrypted AES key.")

        # Create a temporary file for decrypted content
        with tempfile.NamedTemporaryFile(delete=False, prefix="received_temp_", suffix=".bin") as temp_output_file:
            temp_output_filepath = temp_output_file.name
        
        print(f"Created temporary file: {temp_output_filepath}")

        # 3. Receive encrypted chunks, decrypt, and write to temp file
        encrypted_bytes_received = 0
        with open(temp_output_filepath, "wb") as f_temp:
            while encrypted_bytes_received < total_encrypted_payload_size:
                encrypted_chunk_with_tag = recv_message(sock, "binary") # This will read the length prefix and then the payload
                if encrypted_chunk_with_tag is None:
                    raise ConnectionResetError(f"Broker disconnected during chunk transfer for {file_id}.")

                # Separate ciphertext and tag
                if len(encrypted_chunk_with_tag) < GCM_TAG_SIZE:
                    raise ValueError("Received chunk too small to contain GCM tag.")
                
                tag = encrypted_chunk_with_tag[-GCM_TAG_SIZE:]
                ciphertext = encrypted_chunk_with_tag[:-GCM_TAG_SIZE]

                try:
                    decrypted_chunk = decrypt_data_aes_gcm(ciphertext, tag, aes_key, nonce)
                    f_temp.write(decrypted_chunk)
                    encrypted_bytes_received += len(encrypted_chunk_with_tag) # Track actual bytes received from broker
                    print(f"Received and decrypted {encrypted_bytes_received}/{total_encrypted_payload_size} encrypted bytes.")
                except Exception as e:
                    raise Exception(f"Decryption failed for chunk: {e}")

        # After receiving all encrypted chunks, verify the actual size of the decrypted file
        actual_decrypted_file_size = os.path.getsize(temp_output_filepath)

        if actual_decrypted_file_size != total_original_file_size:
            raise Exception(f"Received file size mismatch. Expected {total_original_file_size}, got {actual_decrypted_file_size}.")

        print(f"All chunks received and decrypted for file {file_id}.")

        # 4. Calculate SHA-256 hash of the decrypted file
        calculated_hash = calculate_sha256(temp_output_filepath)

        # 5. Compare hashes
        if calculated_hash != original_hash:
            raise Exception(f"Hash mismatch! Original: {original_hash.hex()}, Calculated: {calculated_hash.hex()}")
        print("File hash verified successfully.")

        # If all checks pass, rename the temporary file
        os.rename(temp_output_filepath, output_filename)
        print(f"File {file_id} successfully received and saved as '{output_filename}'.")
        send_message(sock, "json", {"status": "success", "message": "File received and verified."})

    except ConnectionRefusedError:
        print(f"Error: Could not connect to the broker at {BROKER_HOST}:{BROKER_PORT}. Please ensure broker.py is running and reachable.")
    except socket.timeout:
        print(f"Error: Connection to the broker at {BROKER_HOST}:{BROKER_PORT} timed out.")
    except (socket.error, ConnectionResetError, ValueError, json.JSONDecodeError) as e:
        print(f"Error during file reception: {e}")
        if temp_output_filepath and os.path.exists(temp_output_filepath):
            os.remove(temp_output_filepath)
            print(f"Deleted temporary file due to error: {temp_output_filepath}")
        try:
            send_message(sock, "json", {"status": "error", "message": f"Receiver error: {e}"})
        except socket.error:
            pass # Broker might have already disconnected
    except Exception as e: # Catch custom exceptions like TTL, hash mismatch, decryption failure
        print(f"Verification or decryption failed: {e}")
        if temp_output_filepath and os.path.exists(temp_output_filepath):
            os.remove(temp_output_filepath)
            print(f"Deleted temporary file due to verification/decryption error: {temp_output_filepath}")
        try:
            send_message(sock, "json", {"status": "error", "message": f"Receiver verification failed: {e}"})
        except socket.error:
            pass # Broker might have already disconnected
    finally:
        sock.close()
        print("Connection to broker closed.")
        # Ensure temp file is deleted if it still exists and wasn't renamed
        if temp_output_filepath and os.path.exists(temp_output_filepath) and not os.path.exists(output_filename):
             os.remove(temp_output_filepath)
             print(f"Ensured temporary file {temp_output_filepath} is deleted.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Receiver program for secure file transfer.")
    parser.add_argument("file_id", help="ID of the file to request from the broker.")
    parser.add_argument("output_filename", help="Name for the received file.")
    parser.add_argument("--private_key", default="receiver_private.pem",
                        help="Path to the receiver's private key (default: receiver_private.pem).")
    args = parser.parse_args()

    receiver_main(args.file_id, args.output_filename, args.private_key)
