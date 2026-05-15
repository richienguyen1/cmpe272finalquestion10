import socket
import threading
import json
import os
import time
import uuid
import tempfile
import shutil

# Constants
BROKER_HOST = 'localhost'
BROKER_PORT = 8080
CHUNK_SIZE = 4 * 1024 * 1024 # 4MB

# In-memory storage for file metadata
# {
#   file_id: {
#       'encrypted_aes_key': bytes,
#       'nonce': bytes,
#       'original_hash': bytes,
#       'ttl_expiry_timestamp': float,
#       'total_original_file_size': int, # Original file size
#       'total_encrypted_payload_size': int, # Total size of encrypted data + tags
#       'file_path_on_broker': str, # Path to the temp file storing encrypted chunks
#       'current_received_encrypted_size': int,
#       'status': 'uploading' | 'ready' | 'failed' | 'expired'
#   }
# }
stored_files = {}
stored_files_lock = threading.Lock()

# Temporary directory for storing encrypted file chunks
TEMP_STORAGE_DIR = tempfile.mkdtemp(prefix="broker_storage_")
print(f"Broker temporary storage directory: {TEMP_STORAGE_DIR}")

def send_message(sock, message_type, data):
    """Helper to send structured messages (JSON metadata or binary data)"""
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

def handle_sender_upload(conn, addr):
    print(f"Handling upload from {addr}")
    file_id = None
    file_path_on_broker = None
    try:
        # 1. Receive initial metadata from sender
        metadata = recv_message(conn, "json")
        if metadata is None:
            print(f"Sender {addr} disconnected during metadata reception.")
            return

        file_id = metadata['file_id']
        encrypted_aes_key = bytes.fromhex(metadata['encrypted_aes_key'])
        nonce = bytes.fromhex(metadata['nonce'])
        original_hash = bytes.fromhex(metadata['original_hash'])
        ttl_seconds = metadata['ttl_seconds']
        total_original_file_size = metadata['total_original_file_size']
        total_encrypted_payload_size = metadata['total_encrypted_payload_size']

        ttl_expiry_timestamp = time.time() + ttl_seconds

        print(f"Received metadata for file_id: {file_id}")

        # Create a temporary file to store encrypted chunks
        temp_file_name = f"encrypted_file_{file_id}.bin"
        file_path_on_broker = os.path.join(TEMP_STORAGE_DIR, temp_file_name)

        with stored_files_lock:
            if file_id in stored_files:
                print(f"Error: File ID {file_id} already exists.")
                send_message(conn, "json", {"status": "error", "message": "File ID already exists"})
                return
            stored_files[file_id] = {
                'encrypted_aes_key': encrypted_aes_key,
                'nonce': nonce,
                'original_hash': original_hash,
                'ttl_expiry_timestamp': ttl_expiry_timestamp,
                'total_original_file_size': total_original_file_size,
                'total_encrypted_payload_size': total_encrypted_payload_size,
                'file_path_on_broker': file_path_on_broker,
                'current_received_encrypted_size': 0,
                'status': 'uploading'
            }

        send_message(conn, "json", {"status": "ack_metadata"})

        # 2. Receive encrypted file chunks
        with open(file_path_on_broker, "wb") as f:
            received_encrypted_size = 0
            while received_encrypted_size < total_encrypted_payload_size:
                chunk_data = recv_message(conn, "binary")
                if chunk_data is None:
                    raise ConnectionResetError(f"Sender {addr} disconnected during chunk transfer for {file_id}.")
                f.write(chunk_data)
                received_encrypted_size += len(chunk_data)

                with stored_files_lock:
                    stored_files[file_id]['current_received_encrypted_size'] = received_encrypted_size

        with stored_files_lock:
            if received_encrypted_size == total_encrypted_payload_size:
                stored_files[file_id]['status'] = 'ready'
                print(f"File {file_id} uploaded successfully from {addr}. Encrypted Size: {received_encrypted_size} bytes.")
                send_message(conn, "json", {"status": "success", "message": "File uploaded successfully"})
            else:
                stored_files[file_id]['status'] = 'failed'
                print(f"File {file_id} upload failed from {addr}: size mismatch. Expected {total_encrypted_payload_size}, got {received_encrypted_size}.")
                send_message(conn, "json", {"status": "error", "message": "File upload incomplete"})

    except (socket.error, ConnectionResetError, ValueError, json.JSONDecodeError) as e:
        print(f"Error during sender upload from {addr} for file {file_id}: {e}")
        if file_id:
            with stored_files_lock:
                if file_id in stored_files:
                    stored_files[file_id]['status'] = 'failed'
        if file_path_on_broker and os.path.exists(file_path_on_broker):
            os.remove(file_path_on_broker)
        try:
            send_message(conn, "json", {"status": "error", "message": f"Broker error: {e}"})
        except socket.error:
            pass # Sender might have already disconnected
    finally:
        conn.close()
        print(f"Connection with sender {addr} closed.")
        # If upload failed, remove the entry and file
        if file_id:
            with stored_files_lock:
                if file_id in stored_files and stored_files[file_id]['status'] == 'failed':
                    print(f"Cleaning up failed upload for {file_id}")
                    if os.path.exists(stored_files[file_id]['file_path_on_broker']):
                        os.remove(stored_files[file_id]['file_path_on_broker'])
                    del stored_files[file_id]


def handle_receiver_download(conn, addr):
    print(f"Handling download for {addr}")
    file_id = None
    try:
        # 1. Receive file ID request from receiver
        request = recv_message(conn, "json")
        if request is None:
            print(f"Receiver {addr} disconnected during request reception.")
            return

        file_id = request.get('file_id')
        if not file_id:
            send_message(conn, "json", {"status": "error", "message": "Missing file_id"})
            return

        with stored_files_lock:
            file_info = stored_files.get(file_id)

        if not file_info:
            print(f"File ID {file_id} not found for {addr}.")
            send_message(conn, "json", {"status": "error", "message": "File not found"})
            return

        if file_info['status'] != 'ready':
            print(f"File {file_id} not ready for download (status: {file_info['status']}).")
            send_message(conn, "json", {"status": "error", "message": "File not ready for download"})
            return

        if time.time() > file_info['ttl_expiry_timestamp']:
            print(f"File {file_id} expired for {addr}.")
            send_message(conn, "json", {"status": "error", "message": "File expired"})
            # Mark for immediate cleanup
            with stored_files_lock:
                if file_id in stored_files:
                    stored_files[file_id]['status'] = 'expired'
            return

        print(f"Serving file {file_id} to {addr}.")

        # 2. Send metadata to receiver
        metadata_to_send = {
            'encrypted_aes_key': file_info['encrypted_aes_key'].hex(),
            'nonce': file_info['nonce'].hex(),
            'original_hash': file_info['original_hash'].hex(),
            'ttl_expiry_timestamp': file_info['ttl_expiry_timestamp'], # For receiver to check TTL
            'total_original_file_size': file_info['total_original_file_size'], # For receiver to verify final size
            'total_encrypted_payload_size': file_info['total_encrypted_payload_size'] # For receiver to know when to stop receiving encrypted chunks
        }
        send_message(conn, "json", {"status": "success", "metadata": metadata_to_send})

        # 3. Send encrypted file chunks
        with open(file_info['file_path_on_broker'], "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                send_message(conn, "binary", chunk)
        print(f"Finished sending file {file_id} to {addr}.")

        # Wait for receiver's final status
        receiver_status = recv_message(conn, "json")
        if receiver_status and receiver_status.get('status') == 'success':
            print(f"Receiver {addr} confirmed successful download of {file_id}. Deleting file from broker.")
            with stored_files_lock:
                if file_id in stored_files:
                    if os.path.exists(stored_files[file_id]['file_path_on_broker']):
                        os.remove(stored_files[file_id]['file_path_on_broker'])
                    del stored_files[file_id]
        else:
            print(f"Receiver {addr} reported failure or disconnected for {file_id}. Status: {receiver_status}. Deleting file from broker.")
            with stored_files_lock:
                if file_id in stored_files:
                    if os.path.exists(stored_files[file_id]['file_path_on_broker']):
                        os.remove(stored_files[file_id]['file_path_on_broker'])
                    del stored_files[file_id]


    except (socket.error, ConnectionResetError, ValueError, json.JSONDecodeError) as e:
        print(f"Error during receiver download for {file_id} from {addr}: {e}")
        # If an error occurs during download, clean up the file on the broker
        with stored_files_lock:
            if file_id in stored_files:
                if os.path.exists(stored_files[file_id]['file_path_on_broker']):
                    os.remove(stored_files[file_id]['file_path_on_broker'])
                del stored_files[file_id]
        try:
            send_message(conn, "json", {"status": "error", "message": f"Broker error: {e}"})
        except socket.error:
            pass # Receiver might have already disconnected
    finally:
        conn.close()
        print(f"Connection with receiver {addr} closed.")

def cleanup_expired_files():
    """Periodically checks for and deletes expired files from storage."""
    while True:
        time.sleep(5) # Check every 5 seconds
        now = time.time()
        files_to_delete = []
        with stored_files_lock:
            for file_id, info in list(stored_files.items()): # Use list() to allow modification during iteration
                if info['status'] == 'ready' and now > info['ttl_expiry_timestamp']:
                    files_to_delete.append(file_id)
                elif info['status'] == 'expired' or info['status'] == 'failed':
                    files_to_delete.append(file_id)

            for file_id in files_to_delete:
                print(f"Cleaning up expired/failed file: {file_id}")
                file_path = stored_files[file_id]['file_path_on_broker']
                if os.path.exists(file_path):
                    os.remove(file_path)
                del stored_files[file_id]

def broker_main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((BROKER_HOST, BROKER_PORT))
    server_socket.listen(5)
    print(f"Broker listening on {BROKER_HOST}:{BROKER_PORT}")

    cleanup_thread = threading.Thread(target=cleanup_expired_files, daemon=True)
    cleanup_thread.start()

    try:
        while True:
            conn, addr = server_socket.accept()
            print(f"Accepted connection from {addr}")
            try:
                # First message from client should be a command (UPLOAD or DOWNLOAD)
                command_bytes = recv_exactly(conn, 4)
                if not command_bytes:
                    conn.close(); continue
                command_len = int.from_bytes(command_bytes, 'big')
                command = recv_exactly(conn, command_len).decode('utf-8')

                if command == "UPLOAD":
                    thread = threading.Thread(target=handle_sender_upload, args=(conn, addr))
                    thread.start()
                elif command == "DOWNLOAD":
                    thread = threading.Thread(target=handle_receiver_download, args=(conn, addr))
                    thread.start()
                else:
                    print(f"Unknown command '{command}' from {addr}. Closing connection.")
                    conn.close()
            except socket.error as e:
                print(f"Error receiving command from {addr}: {e}. Closing connection.")
                conn.close()
            except Exception as e:
                print(f"Unexpected error in main loop for {addr}: {e}. Closing connection.")
                conn.close()
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received. Shutting down the broker...")
    finally:
        server_socket.close()
        # Clean up temporary storage directory
        if os.path.exists(TEMP_STORAGE_DIR):
            shutil.rmtree(TEMP_STORAGE_DIR)
            print(f"Cleaned up temporary storage directory: {TEMP_STORAGE_DIR}")

if __name__ == "__main__":
    broker_main()
