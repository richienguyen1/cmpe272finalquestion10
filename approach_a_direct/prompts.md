# initial generation from prompt [claude]
Create a Python system where a sender program securely transfers a file to a receiver program through a direct connection without using a middleman/broker between the two programs.
The sender program is on localhost:8080 while the receiver program is on localhost:8081.
The file must be streamed for the transfer and split into chunks of fixed size 4MB. The transfer must support file sizes up to 8GB.
The file to transfer is specified by the sender program with an input argument specifying the file name.
Before transferring the file, the file must be cryptographically hashed using the SHA-256 algorithm. The expected hash is sent to the receiver along with the file. If the hash does not match with the sent file, raise an exception stating that the received file does not match the expected hash.
As the file is transferred, create a temp file that contains the compiled chunks of the transferred file. If the transfer is finished and no exceptions are raised, save the temp file as the received file. If any exceptions are raised during the transfer process, immediately stop the transfer and delete the temp file.
The Python programs should use the standard cryptography library.

# updates to programs to include details from architecture diagram [claude]
Modify the sender.py and receiver.py programs to include the following changes:
- Follow the provided architecture diagram to use public key infrastructure for mutual authentication, connection drop protection, and symmetric key encryption
- The symmetric key encryption should use the AEAD algorithm while the public key infrastructure should use the RSA algorithm.
- The resulting modifications to the sender and receiver programs should enforce using the TCP protocol for communication and file transfer.

# asking about what the .PEM files are for the PKI keys from generated code [claude]
What would the .PEM files be for the public and private keys of the receiver? Should they follow a specific text format for the RSA algorithm? Would changing the private key requirement from an external .PEM file to an internal variable in receiver.py be more secure?

# updating programs to generate public/private keys of receiver.py and changing input arguments [claude]
Modify the sender.py and receiver.py programs to include the following changes:
- When the receiver.py program is first started, generate the public and private keys that are used in the RSA algorithm and architecture diagram as receiver_public.pem and receiver_private.pem files respectively.
- For sender.py, keep the input argument that asks for the receiver_public.pem file. For receiver.py, remove the input argument that asks for the receiver_private.pem file and instead use it in the receive_file() function.

# updating sender.py to remove temp files if receiver is stopped during transfer [claude]
Modify the sender.py program to include the following changes:
- When the receiver.py program is closed during the file transfer, raise an Exception and remove the temp file created when transferring the file.