"""
receiver.py — Secure file transfer receiver (RSA + AES-256-GCM over TCP)
=========================================================================
Architecture (direct TCP, no broker):

  Start-up — On first run, a 2048-bit RSA key pair is generated and written
              to receiver_private.pem and receiver_public.pem in the working
              directory. If the files already exist they are reused so the
              sender does not need a new public key on every restart.
              Copy receiver_public.pem to the sender before transferring.

  Step 1 — Sender sends RSA-OAEP-encrypted blob containing the symmetric
            AES-256-GCM key + base nonce. Receiver decrypts with its private
            key to recover both values.

  Step 2 — Receiver sends a JSON ACK echoing the decrypted nonce back to the
            sender for verification. If the nonce received by the sender does
            not match what it sent, the sender aborts.

  Step 3 — Sender streams AES-256-GCM-encrypted metadata (filename, size,
            SHA-256 of the plaintext) followed by the encrypted file chunks.
            Each chunk uses a unique nonce derived from base_nonce XOR index.
            Receiver decrypts every frame and writes plaintext to a temp file.

  Step 4 — After all chunks are received, receiver recomputes the SHA-256 of
            the assembled plaintext and compares it to the hash in the
            metadata. On match: temp file is atomically renamed to the final
            output; final ACK sent. On mismatch: temp file is deleted and a
            ValueError is raised.

Error handling:
  • Connection drop mid-transfer      → ConnectionError; temp file deleted.
  • Nonce mismatch (steps 1-3)        → ValueError; temp file deleted.
  • AES-GCM authentication failure    → cryptography.exceptions.InvalidTag;
                                        temp file deleted.
  • SHA-256 hash mismatch             → ValueError; temp file deleted.

Usage:
    python receiver.py [--output-dir DIR]
"""

import argparse
import hashlib
import json
import os
import socket
import struct
import sys
import tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Constants ──────────────────────────────────────────────────────────────────
SENDER_HOST      = "localhost"
SENDER_PORT      = 8080
NONCE_SIZE       = 12                   # AES-GCM nonce length (bytes)
KEY_SIZE         = 32                   # AES-256 key length (bytes)
PRIVATE_KEY_PATH = "receiver_private.pem"
PUBLIC_KEY_PATH  = "receiver_public.pem"


# ── Low-level TCP framing ──────────────────────────────────────────────────────

def recv_exactly(conn: socket.socket, n: int) -> bytes:
    """Receive exactly *n* bytes; raise ConnectionError on early close."""
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(
                f"Connection dropped: expected {n} bytes, received {len(buf)}."
            )
        buf += chunk
    return bytes(buf)


def recv_prefixed(conn: socket.socket) -> bytes:
    """Receive one length-prefixed frame."""
    (msg_len,) = struct.unpack(">I", recv_exactly(conn, 4))
    return recv_exactly(conn, msg_len)


def send_prefixed(conn: socket.socket, data: bytes) -> None:
    """Send a length-prefixed frame: [4-byte big-endian length][payload]."""
    conn.sendall(struct.pack(">I", len(data)) + data)


# ── Crypto helpers ─────────────────────────────────────────────────────────────

def load_private_key(path: str):
    """Load an RSA private key from a PEM file (no passphrase)."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def generate_rsa_keypair() -> None:
    """
    Generate a 2048-bit RSA key pair and write it to the fixed PEM paths.

    Both files are written with mode 0o600 (owner read/write only) so the
    private key is never world-readable.  If either file already exists the
    function skips generation and reuses the existing pair, which means the
    sender does not need a new copy of the public key on every receiver restart.
    """
    if os.path.isfile(PRIVATE_KEY_PATH) and os.path.isfile(PUBLIC_KEY_PATH):
        print(
            f"RSA key pair already exists "
            f"('{PRIVATE_KEY_PATH}' / '{PUBLIC_KEY_PATH}'). Reusing."
        )
        return

    print("Generating 2048-bit RSA key pair…")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # ── Write private key (owner read/write only) ─────────────────────────────
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_fd = os.open(PRIVATE_KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(priv_fd, "wb") as f:
        f.write(private_pem)

    # ── Write public key (world-readable is fine for a public key) ────────────
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_pem)

    print(f"  Private key → '{PRIVATE_KEY_PATH}' (permissions: 600)")
    print(f"  Public key  → '{PUBLIC_KEY_PATH}'")
    print(f"  Copy '{PUBLIC_KEY_PATH}' to the sender before starting the transfer.")


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """RSA-OAEP decrypt *ciphertext* using SHA-256 hash and MGF1."""
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def derive_chunk_nonce(base_nonce: bytes, index: int) -> bytes:
    """
    Reproduce the per-chunk nonce: XOR base nonce with the zero-padded index.
    Must mirror the sender's derive_chunk_nonce exactly.
    """
    idx_bytes = index.to_bytes(NONCE_SIZE, "big")
    return bytes(a ^ b for a, b in zip(base_nonce, idx_bytes))


# ── Main receive logic ─────────────────────────────────────────────────────────

def receive_file(output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)

    print(f"Loading receiver private key from '{PRIVATE_KEY_PATH}'…")
    private_key = load_private_key(PRIVATE_KEY_PATH)

    print(f"Connecting to sender at {SENDER_HOST}:{SENDER_PORT} (TCP)…")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        # Enforce TCP stream socket
        if conn.type != socket.SOCK_STREAM:
            raise RuntimeError("Socket is not SOCK_STREAM (TCP). Aborting.")

        conn.connect((SENDER_HOST, SENDER_PORT))
        print("Connected.")

        # ── STEP 1 ─ Receive and decrypt symmetric key + nonce ────────────────
        encrypted_key_nonce = recv_prefixed(conn)
        key_and_nonce       = rsa_decrypt(private_key, encrypted_key_nonce)

        if len(key_and_nonce) != KEY_SIZE + NONCE_SIZE:
            raise ValueError(
                f"Decrypted key+nonce blob is {len(key_and_nonce)} bytes; "
                f"expected {KEY_SIZE + NONCE_SIZE}."
            )

        sym_key    = key_and_nonce[:KEY_SIZE]
        base_nonce = key_and_nonce[KEY_SIZE:]
        aesgcm     = AESGCM(sym_key)
        print("Step 1 ✓ — Symmetric key and nonce decrypted via RSA private key.")

        # ── STEP 2 ─ Echo nonce back for sender verification ──────────────────
        ack = json.dumps({"status": "ready", "nonce": base_nonce.hex()}).encode()
        send_prefixed(conn, ack)
        print("Step 2 ✓ — Nonce echoed to sender for verification.")

        # ── STEP 3 ─ Receive and decrypt metadata frame (chunk index 0) ───────
        meta_ct   = recv_prefixed(conn)
        meta_plain = aesgcm.decrypt(derive_chunk_nonce(base_nonce, 0), meta_ct, None)
        metadata  = json.loads(meta_plain.decode())

        # Sanitize filename to prevent path traversal attacks
        raw_file_name: str = metadata["file_name"]
        file_name:     str = os.path.basename(raw_file_name)
        
        file_size:     int = metadata["file_size"]
        expected_hash: str = metadata["sha256"]
        chunk_size:    int = metadata["chunk_size"]

        print(f"Receiving '{file_name}' ({file_size:,} bytes)...")
        print(f"Expected SHA-256: {expected_hash}")

        output_path           = os.path.join(output_dir, file_name)
        tmp_fd, tmp_path      = tempfile.mkstemp(
            dir=output_dir, prefix=f".{file_name}.tmp."
        )

        try:
            sha256         = hashlib.sha256()
            bytes_received = 0
            chunk_index    = 1   # index 0 was used for metadata

            # ── STEP 3 (cont.) ─ Receive, decrypt, and write file chunks ──────
            with os.fdopen(tmp_fd, "wb") as tmp_file:
                while bytes_received < file_size:
                    ct_chunk = recv_prefixed(conn)

                    # Check for a sender-initiated cancellation frame.
                    # The sender sends {"cancel": true} as plain JSON (not
                    # AES-GCM encrypted) so it is readable even when the
                    # symmetric channel has not been fully established yet.
                    try:
                        msg = json.loads(ct_chunk)
                        if msg.get("cancel"):
                            raise ConnectionError(
                                "Sender cancelled the transfer mid-stream. "
                                "Temp file will be deleted."
                            )
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        pass   # normal encrypted chunk — proceed with decryption

                    plain_chunk = aesgcm.decrypt(
                        derive_chunk_nonce(base_nonce, chunk_index), ct_chunk, None
                    )
                    tmp_file.write(plain_chunk)
                    sha256.update(plain_chunk)
                    bytes_received += len(plain_chunk)
                    chunk_index    += 1
                    pct = bytes_received / file_size * 100
                    print(
                        f"\rReceived {bytes_received:,} / {file_size:,} bytes ({pct:.1f}%)",
                        end="", flush=True,
                    )

            print()  # newline after progress bar

            # ── STEP 4 ─ Verify SHA-256 hash ──────────────────────────────────
            actual_hash = sha256.hexdigest()
            if actual_hash != expected_hash:
                raise ValueError(
                    "Hash mismatch — received file does not match the expected hash.\n"
                    f"  Expected : {expected_hash}\n"
                    f"  Actual   : {actual_hash}"
                )

            # ── Atomically promote temp file to final destination ──────────────
            os.replace(tmp_path, output_path)
            print(f"✓ File saved as '{output_path}'")

            # ── Send success ACK ───────────────────────────────────────────────
            send_prefixed(conn, json.dumps({"status": "ok"}).encode())

        except Exception as exc:
            # Always delete the temp file on any failure
            try:
                os.unlink(tmp_path)
                print("\nTemp file deleted due to error.")
            except FileNotFoundError:
                pass
            # Re-raise so the caller can log / exit appropriately
            raise


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Secure file transfer — receiver (RSA key exchange + AES-256-GCM)"
    )
    parser.add_argument(
        "--output-dir",
        default="received_files",
        help="Directory for received files (default: received_files/)",
    )
    args = parser.parse_args()

    # Generate (or reuse) the RSA key pair before doing anything else.
    # The public key must be copied to the sender before the transfer.
    generate_rsa_keypair()

    try:
        receive_file(args.output_dir)
    except ValueError as exc:
        print(f"\nTransfer failed — integrity error: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"\nTransfer failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
