Architecture diagram can be found with the architectdiagram.png file

# Used technologies/algorithms
- RSA/Public Key Infrastructure: used for mutual authentication between sender and receiver by encrypting a symmetric encryption key + nonce
- AES-256-GCM: used as symmetric encryption key to encrypt the file + hash to send to the receiver
- SHA-256: used to create a hash for the file as a comparison for the receiver

# Threat models comparison
- "Passive eavesdropper records the entire TCP stream.": The transferred file is always encrypted with the AES-256-GCM key on the wire. This also applies to the key itself by being transferred while being encrypted by the RSA algorithm.
- "Active man-in-the-middle modifies bytes mid-flight.": The SHA-256 hash makes the receiver verify the file contents/quality before finalizing the transfer. If there are any differences, the receiver drops the connection and removes the file.
- "Attacker spoofs the sender or the receiver.": The RSA public key infrastructure used between the sender and receiver validates both of the programs. If the attacker uses a different public/private key, decrypting the symmetric encryption key does not work.
- "Replay of an earlier valid transfer.": Providing the nonce per session provides freshness of the transfer. The transfer does not work if the nonce values are changed/different. In addition, a TTL value is provided with the file transfer. If the receiver obtains the file but the TTL value is expired, the receiver drops the file.
- "Connection drops at 80% transferred.": The receiver and sender drop/remove the partial file if the connection is dropped during it. This also applies to file transfers between the sender, broker, and receiver.
- "Untrusted intermediary (broker / object store), if used.": All stored data (file, hash, symmetric key) are already encrypted with either the public key infrastructure or the symmetric key. In addition, the TTL value makes the stored data have limited lifetimes.