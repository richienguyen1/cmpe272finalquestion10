# Common pitfalls
- encryption in CBC or CTR without using MAC
- reusing same key + nonce pair across encryption chunks
- Computing the integrity hash of only the ciphertext instead of the plaintext
- Trusting first byte sent before authenticating sender
- Writing received bytes to final filename before verification
- Self-signed cert and skip verification in client/sender/receiver
- Storing symmetric keys, IV value, passphrase in logs
- treating TCP FIN message as complete file proof

# Threat models and how to deal with them
- passive eavesdropper records TCP stream: file bytes must appear as ciphertext on wire, key never travels unencrypted
- active man-in-the-middle attack modifies transfer bytes mid-flight: receiver aborts cleanly if it detects modification of file compared to received hash
- attacker spoofs sender or receiver: mutual authentication closes if wrong key/certification are presented
- replay attack plays earlier valid transfer: session nonces/handshake/fresh timestamp prevent replay attacks
- connection drops while parts of file are untransferred: receiver denies partial file as valid and stops connection
- untrusted intermediary/broker: plaintext and long-lived keys never reach broker, files stored in broker are not leaked if broker is compromised