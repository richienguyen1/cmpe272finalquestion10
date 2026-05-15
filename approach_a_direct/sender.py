"""
sender.py — Secure file transfer sender (RSA + AES-256-GCM over TCP)
=====================================================================
Architecture (direct TCP, no broker):

  Step 1 — Sender generates a random AES-256-GCM symmetric key + nonce,
            encrypts them with the receiver's RSA public key (OAEP/SHA-256),
            and sends the ciphertext to the receiver over TCP.

  Step 2 — Receiver decrypts key + nonce with its RSA private key and sends
            back a JSON ACK confirming the nonce it derived. Sender verifies
            the echoed nonce matches before proceeding; mismatch raises
            ValueError and closes the connection immediately.

  Step 3 — Sender computes SHA-256 of the plaintext file, then streams it in
            4 MB chunks. Every chunk (and the metadata frame carrying the hash)
            is AEAD-encrypted with AES-256-GCM. Each chunk gets a unique nonce
            derived by XOR-ing the base nonce with the chunk's sequential index
            so the receiver can reproduce each nonce without extra round-trips.

  Step 4 — Receiver decrypts each chunk, verifies the SHA-256, and sends a
            final ACK. Sender raises ValueError on error ACK.

Error handling:
  • Receiver closes connection mid-transfer → ReceiverDisconnectedError is
      raised. The sender first attempts to send a cancellation frame so the
      receiver can delete its temp file, then re-raises the exception.
  • OS-level broken-pipe / connection-reset  → wrapped in
      ReceiverDisconnectedError with the same cancellation attempt.
  • Nonce mismatch after step 2      → ValueError; connection closed.
  • Hash mismatch reported by peer   → ValueError raised on sender.

Usage:
    python sender.py <file_path> [--receiver-pubkey receiver_public.pem]

Note:
    The RSA key pair is generated automatically when receiver.py starts for the
    first time. Copy receiver_public.pem from the receiver to the sender before
    running this program.
"""

import argparse
import hashlib
import json
import os
import socket
import struct
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Constants ──────────────────────────────────────────────────────────────────
CHUNK_SIZE  = 4 * 1024 * 1024   # 4 MB plaintext chunk
HOST        = "localhost"
PORT        = 8080
NONCE_SIZE  = 12                 # AES-GCM standard nonce (bytes)


# ── Custom exception ───────────────────────────────────────────────────────────

class ReceiverDisconnectedError(Exception):
    """Raised when the receiver closes the connection before the transfer ends."""


# ── Low-level TCP framing ──────────────────────────────────────────────────────

def send_prefixed(conn: socket.socket, data: bytes) -> None:
    """
    Send a length-prefixed frame: [4-byte big-endian length][payload].
    BrokenPipeError and ConnectionResetError are re-raised as
    ReceiverDisconnectedError so all drop scenarios surface consistently.
    """
    try:
        conn.sendall(struct.pack(">I", len(data)) + data)
    except (BrokenPipeError, ConnectionResetError) as exc:
        raise ReceiverDisconnectedError(
            "Receiver closed the connection while sending data."
        ) from exc


def recv_exactly(conn: socket.socket, n: int) -> bytes:
    """
    Receive exactly *n* bytes.
    An empty read (peer closed) is raised as ReceiverDisconnectedError;
    ConnectionResetError is wrapped the same way.
    """
    buf = bytearray()
    try:
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ReceiverDisconnectedError(
                    f"Receiver closed the connection after {len(buf)}/{n} bytes."
                )
            buf += chunk
    except ConnectionResetError as exc:
        raise ReceiverDisconnectedError(
            "Receiver reset the connection unexpectedly."
        ) from exc
    return bytes(buf)


def recv_prefixed(conn: socket.socket) -> bytes:
    """Receive one length-prefixed frame."""
    (msg_len,) = struct.unpack(">I", recv_exactly(conn, 4))
    return recv_exactly(conn, msg_len)


def try_send_cancel(conn: socket.socket) -> None:
    """
    Best-effort: send a cancellation frame to the receiver so it can delete
    its temp file. Swallows all exceptions — the connection may already be dead.
    """
    try:
        cancel = json.dumps({"cancel": True}).encode()
        conn.sendall(struct.pack(">I", len(cancel)) + cancel)
    except Exception:
        pass


# ── Crypto helpers ─────────────────────────────────────────────────────────────

def load_receiver_public_key(path: str):
    """Load an RSA public key from a PEM file."""
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    """RSA-OAEP encrypt *plaintext* using SHA-256 hash and MGF1."""
    return public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def derive_chunk_nonce(base_nonce: bytes, index: int) -> bytes:
    """
    Produce a unique per-chunk nonce by XOR-ing the 12-byte base nonce with
    the chunk index (zero-padded to 12 bytes). Index 0 is reserved for the
    metadata frame; file chunks start at index 1.
    """
    idx_bytes = index.to_bytes(NONCE_SIZE, "big")
    return bytes(a ^ b for a, b in zip(base_nonce, idx_bytes))


def compute_sha256(file_path: str) -> str:
    """Return the hex-encoded SHA-256 digest of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(block)
    return h.hexdigest()


# ── Main transfer logic ────────────────────────────────────────────────────────

def transfer_file(file_path: str, pubkey_path: str) -> None:
    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)

    # ── Pre-flight ────────────────────────────────────────────────────────────
    print(f"Loading receiver public key from '{pubkey_path}'…")
    receiver_pubkey = load_receiver_public_key(pubkey_path)

    print(f"Computing SHA-256 for '{file_name}' ({file_size:,} bytes)…")
    plaintext_hash = compute_sha256(file_path)
    print(f"SHA-256: {plaintext_hash}")

    # Generate a fresh 256-bit symmetric key and 96-bit base nonce per session
    sym_key    = AESGCM.generate_key(bit_length=256)  # 32 random bytes
    base_nonce = os.urandom(NONCE_SIZE)                # 12 random bytes
    aesgcm     = AESGCM(sym_key)

    # ── Open TCP server (sender listens; receiver initiates the connection) ───
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)
        print(f"Sender listening on {HOST}:{PORT} (TCP) — waiting for receiver…")
        conn, addr = srv.accept()

    with conn:
        # Sanity-check that the OS gave us a proper TCP stream socket
        if conn.type != socket.SOCK_STREAM:
            raise RuntimeError("Accepted socket is not SOCK_STREAM (TCP). Aborting.")
        print(f"Receiver connected from {addr}")

        try:
            # ── STEP 1 ─ Encrypt and send symmetric key + nonce via RSA ──────
            # Concatenate key ‖ nonce (44 bytes) so both travel in one RSA envelope.
            key_and_nonce       = sym_key + base_nonce        # 32 + 12 = 44 bytes
            encrypted_key_nonce = rsa_encrypt(receiver_pubkey, key_and_nonce)
            send_prefixed(conn, encrypted_key_nonce)
            print("Step 1 ✓ — Encrypted symmetric key + nonce sent.")

            # ── STEP 2 ─ Verify nonce echo from receiver ──────────────────────
            ack_data = json.loads(recv_prefixed(conn).decode())

            if ack_data.get("status") != "ready":
                raise ValueError(
                    "Receiver not ready after key exchange. "
                    f"Error: {ack_data.get('error', 'unknown')}"
                )

            echoed_nonce = bytes.fromhex(ack_data["nonce"])
            if echoed_nonce != base_nonce:
                raise ValueError(
                    "Nonce mismatch — possible replay or MITM attack. "
                    "Security verification failed. Connection closed."
                )
            print("Step 2 ✓ — Nonce verified. Encrypted channel established.")

            # ── STEP 3 ─ Stream encrypted metadata frame (chunk index 0) ─────
            metadata_plain = json.dumps(
                {
                    "file_name":  file_name,
                    "file_size":  file_size,
                    "sha256":     plaintext_hash,
                    "chunk_size": CHUNK_SIZE,
                }
            ).encode()
            meta_ct = aesgcm.encrypt(
                derive_chunk_nonce(base_nonce, 0), metadata_plain, None
            )
            send_prefixed(conn, meta_ct)
            print("Step 3 ✓ — Encrypted metadata sent. Streaming file chunks…")

            # ── STEP 3 (cont.) ─ Stream encrypted file chunks ────────────────
            bytes_sent  = 0
            chunk_index = 1   # index 0 was used for metadata

            with open(file_path, "rb") as f:
                while True:
                    plain_chunk = f.read(CHUNK_SIZE)
                    if not plain_chunk:
                        break
                    ct_chunk = aesgcm.encrypt(
                        derive_chunk_nonce(base_nonce, chunk_index), plain_chunk, None
                    )
                    send_prefixed(conn, ct_chunk)
                    bytes_sent  += len(plain_chunk)
                    chunk_index += 1
                    pct = bytes_sent / file_size * 100
                    print(
                        f"\rSent {bytes_sent:,} / {file_size:,} bytes ({pct:.1f}%)",
                        end="", flush=True,
                    )

            print()  # newline after progress bar

            # ── STEP 4 ─ Wait for final integrity ACK ─────────────────────────
            final_ack = json.loads(recv_prefixed(conn).decode())
            if final_ack.get("status") == "ok":
                print("✓ Transfer complete — receiver confirmed hash match.")
            else:
                raise ValueError(
                    f"Receiver reported an error: {final_ack.get('error', 'unknown')}"
                )

        except ReceiverDisconnectedError:
            # The receiver closed mid-transfer. Send a best-effort cancellation
            # frame so the receiver process (if still partially alive) deletes
            # its temp file, then surface the error to the caller.
            print("\nReceiver disconnected — sending cancellation signal…", file=sys.stderr)
            try_send_cancel(conn)
            raise


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Secure file transfer — sender (RSA key exchange + AES-256-GCM)"
    )
    parser.add_argument("file_path", help="Path to the file to transfer")
    parser.add_argument(
        "--receiver-pubkey",
        default="receiver_public.pem",
        help="Receiver's RSA public key PEM file (default: receiver_public.pem)",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.file_path):
        print(f"Error: file '{args.file_path}' not found.", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(args.receiver_pubkey):
        print(f"Error: public key '{args.receiver_pubkey}' not found.", file=sys.stderr)
        sys.exit(1)

    try:
        transfer_file(args.file_path, args.receiver_pubkey)
    except ReceiverDisconnectedError as exc:
        print(f"Transfer aborted: receiver disconnected mid-transfer. ({exc})", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"\nTransfer failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
