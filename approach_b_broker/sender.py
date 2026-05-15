import socket
import json
import os
import time
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import argparse

# --- Cryptography Utility Functions ---
def generate_aes_key():
    """Generates a 256-bit AES key."""
    return os.urandom(32) # 256-bit key

def encrypt_aes_key_with_rsa(aes_key: bytes, public_key_path: str) -> bytes:
    """Encrypts an AES key using RSA public key encryption with OAEP padding."""
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def encrypt_data_aes_gcm(data: bytes, key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    """Encrypts data using AES-256-GCM and returns ciphertext and authentication tag."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return ciphertext, encryptor.tag

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
TTL_SECONDS = 300 # Increased TTL to 5 minutes for 8GB support
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

def sender_main(filepath: str, public_key_path: str):
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found.")
        return

    if not os.path.exists(public_key_path):
        print(f"Error: Public key file '{public_key_path}' not found. Please generate it using generate_keys.py.")
        return

    file_id = str(uuid.uuid4())
    total_original_file_size = os.path.getsize(filepath)

    print(f"Preparing to send file: {filepath} (ID: {file_id}, Original Size: {total_original_file_size} bytes)")

    # 1. Generate AES key and Nonce
    aes_key = generate_aes_key()
    nonce = os.urandom(12) # GCM recommended nonce size is 12 bytes

    # 2. Encrypt AES key with RSA public key
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key_path)

    # 3. Calculate SHA-256 hash of the original file
    original_hash = calculate_sha256(filepath)
    
    # Mathematically calculate encrypted size (much faster for 8GB)
    file_size = os.path.getsize(filepath)
    num_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE if file_size > 0 else 1
    total_encrypted_payload_size = file_size + (num_chunks * GCM_TAG_SIZE)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((BROKER_HOST, BROKER_PORT))
        print(f"Connected to broker at {BROKER_HOST}:{BROKER_PORT}")

        # Send UPLOAD command
        send_message(sock, "command", "UPLOAD")

        # Send metadata
        metadata = {
            'file_id': file_id,
            'encrypted_aes_key': encrypted_aes_key.hex(),
            'nonce': nonce.hex(),
            'original_hash': original_hash.hex(),
            'ttl_seconds': TTL_SECONDS,
            'total_original_file_size': total_original_file_size,
            'total_encrypted_payload_size': total_encrypted_payload_size
        }
        send_message(sock, "json", metadata)
        print("Sent metadata to broker.")

        # Await acknowledgment for metadata
        ack = recv_message(sock, "json")
        if ack is None or ack.get('status') != 'ack_metadata':
            print(f"Broker did not acknowledge metadata or disconnected. Status: {ack}")
            return

        # 4. Read file in chunks, encrypt, and send
        original_bytes_sent = 0
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break

                encrypted_chunk, tag = encrypt_data_aes_gcm(chunk, aes_key, nonce)
                send_message(sock, "binary", encrypted_chunk + tag)
                
                original_bytes_sent += len(chunk)
                print(f"Sent {original_bytes_sent}/{total_original_file_size} bytes ({original_bytes_sent/total_original_file_size:.2%})")

        print(f"All chunks sent for file {file_id}.")

        # Await final status from broker
        final_status = recv_message(sock, "json")
        if final_status and final_status.get('status') == 'success':
            print(f"File {file_id} uploaded successfully to broker.")
        else:
            print(f"File {file_id} upload failed on broker. Status: {final_status}")

    except ConnectionRefusedError:
        print(f"Error: Could not connect to the broker at {BROKER_HOST}:{BROKER_PORT}. Please ensure broker.py is running and reachable.")
    except socket.timeout:
        print(f"Error: Connection to the broker at {BROKER_HOST}:{BROKER_PORT} timed out.")
    except (socket.error, ConnectionResetError, ValueError, json.JSONDecodeError) as e:
        print(f"Error during file transfer: {e}")
    finally:
        sock.close()
        print("Connection to broker closed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sender program for secure file transfer.")
    parser.add_argument("filepath", help="Path to the file to be transferred.")
    parser.add_argument("--public_key", default="receiver_public.pem",
                        help="Path to the receiver's public key (default: receiver_public.pem).")
    args = parser.parse_args()

    sender_main(args.filepath, args.public_key)
