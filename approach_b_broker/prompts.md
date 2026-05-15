# initial generation from prompt and architecture diagram [gemini]
Create a Python system where a sender program transfers a file into an intermediary broker/storage for the receiver to pick up.
The sender program is on localhost:8080 while the receiver program is on localhost:8081.
The file must be streamed for the transfer and split into chunks of fixed size 4MB. The transfer must support file sizes up to 8GB.
The file to transfer is specified by the sender program with an input argument specifying the file name.
As the file is transferred, the file is encrypted using the AES-256-GCM symmetric key algorithm to provide AEAD encryption.
The AES-256-GCM symmetric key itself is encrypted using the RSA public key infrastructure algorithm. The sender uses the receiver's public key (receiver_public.pem) to encrypt the symmetric key.
Before transferring the file, the file must be cryptographically hashed using the SHA-256 algorithm. In addition, a Time to Live value (default 30 seconds) is created.
The sender sends the encrypted file, hash, TTL value, encrypted AES-256-GCM key, and nonce value into the intermediary broker for storage.
As the file is transferred from the intermediary storage to the receiver, create a temp file that contains the compiled chunks of the transferred file. If the transfer is finished and no exceptions are raised, save the temp file as the received file. If any exceptions are raised during the transfer process, immediately stop the transfer and delete the temp file.
The Python programs should use the standard cryptography library.
Do not print out any keys or nonce values into the console.
Enforce using the TCP protocol for file transfer between the sender, intermediary broker, and receiver.
Follow the provided architecture diagram for the sender, intermediary broker, and receiver, along with using the AES-256-GCM symmetric key and RSA public key infrastructure.

# updating broker.py to be able to be closed along with error handling [gemini]
Modify the broker.py file to allow being closed with Ctrl+C. In addition, provide error handling for sender.py and receiver.py if broker.py is unable to be reached.

# attempting to debug issue with broker -> receiver transfer for large files (1+ GB) [gemini]
Is there a reason why the file transfer from the broker to the receiver breaks when transferring files larger than 1GB? For smaller files around 2MB, the transfer works correctly with decryption. However, when I tested this with a file with size 2GB, the transfer between the broker and receiver breaks while returning Socket error while sending message: [WinError 10054] An existing connection was forcibly closed by the remote host. Is there a way for the receiver to be able to transfer files with sizes up to 8GB from the intermediary broker?