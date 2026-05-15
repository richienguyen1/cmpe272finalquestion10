Architecture diagram can be found with the architectdiagram.png file

# Used technologies/algorithms
- RSA/Public Key Infrastructure: used for mutual authentication between sender and receiver by encrypting a symmetric encryption key + nonce
- AES-256-GCM: used as symmetric encryption key to encrypt the file + hash to send to the receiver
- SHA-256: used to create a hash for the file as a comparison for the receiver

# Threat models comparison
- "Passive eavesdropper records the entire TCP stream.": The transferred file is always encrypted with the AES-256-GCM key on the wire. This also applies to the key itself by being transferred while being encrypted by the RSA algorithm.
- "Active man-in-the-middle modifies bytes mid-flight.": The SHA-256 hash makes the receiver verify the file contents/quality before finalizing the transfer. If there are any differences, the receiver drops the connection and removes the file.
- "Attacker spoofs the sender or the receiver.": The RSA public key infrastructure used between the sender and receiver validates both of the programs. If the attacker uses a different public/private key, decrypting the symmetric encryption key does not work.
- "Replay of an earlier valid transfer.": Providing the nonce per session provides freshness of the transfer. The transfer does not work if the nonce values are changed/different.
- "Connection drops at 80% transferred.": The receiver and sender drop/remove the partial file if the connection is dropped during it.
- "Untrusted intermediary (broker / object store), if used.": N/A since intermediary is not used for this approach.