import struct, uuid
from Crypto.Cipher import AES
from Crypto.Util import Padding
from datetime import datetime, timezone

# NOTE: pip install pycryptodome
#       If running on windows, may need to specify `python bchoc` instead of
#       just trying to run via `./bchoc`. Additionally, make sure to utilize
#       the Makefile by using the commands `make` and `make clean`

"""
block.py defines the block data structure that will be used by
every block in the blockchain:

Offset  Length(Bytes)       Field Name - Description
0x00    32* (256 bits)      Previous hash - SHA-256 hash of this block's parent
0x20    8 (64 bits)         Timestamp - Regular Unix timestamp. Must be printed in ISO 8601 format. Stored as an 8-byte float (double)
0x28    32 (256 bits)       Case ID - UUID (Encrypted using AES ECB, stored as hex)
0x48    32 (256 bits)       Evidence item ID - 4 byte int (Encrypted using AES ECB, stored as hex)
0x68    12** (96 bits)      State - must be one of: INITIAL (for initial block only), CHECKEDIN, CHECKEDOUT, DISPOSED, DESTROYED, or RELEASED
0x74    12 (96 bits)        Creator - Free form text w/ max 12 chars
0x80    12 (96 bits)        Owner - Free form text w/ max 16 chars (must be one of Police, Lawyer, Analyst, Executive)
0x8C    4 (32 bits)         Data Length (byte count) - 4-byte int
0x90    0 to 2^32           Data - Free form text w/ byte length specified in Data Length
"""

BLOCK_HEADER_FORMAT = "32s d 32s 32s 12s 12s 12s I"
HEADER_SIZE = struct.calcsize(BLOCK_HEADER_FORMAT)

# 16-byte AES key for encryption/decryption
AES_KEY = b"R0chLi4uLi4uLi4="

# ---------------------------------------------------------------
# Helper crypto/time functions
# ---------------------------------------------------------------
def make_bytes(val) -> bytes:
    """
    Takes in a val (str or bytes) and returns raw bytes
    """
    if isinstance(val, str):
        return val.encode('utf-8')
    elif isinstance(val, bytes):
        return val
    else:
        raise TypeError(f"encrypt() expects str or bytes, got {type(val)}")
    
def encrypt(b: bytes) -> bytes:
    """
    Encrypt a single AES block (ECB) and return 32 ascii hex bytes. If plaintext
    is already 16 bytes, encrypt it as is; if shorter, pad it; if longer, error
    """
    if len(b) > 16:
        raise ValueError("Plaintext too long for 16-byte AES block")
    
    if len(b) < 16:
        b = Padding.pad(b, AES.block_size)  # Pad to 16 bytes

    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    ct = cipher.encrypt(b)                          # 16 raw bytes
    return ct.hex().encode("ascii")  # 32 ascii bytes

def encrypt_id(raw4: bytes) -> bytes:
    """
    Encrypt the 4-byte evidence ID
    """
    if len(raw4) != 4:
        raise ValueError("ERROR: evidence_id must be 4 bytes!")
    
    padded = b'\0'*12 + raw4    # Pad from the left
    ct = AES.new(AES_KEY, AES.MODE_ECB).encrypt(padded)
    return ct.hex().encode("ascii")

def decrypt(hex_cipher: bytes) -> bytes:
    """
    AES‑ECB decrypt and remove PKCS#7 padding, returning UTF‑8 string.
    32 ascii hex bytes to 16 raw bytes
    """
    ct = bytes.fromhex(hex_cipher.decode("ascii"))

    if len(ct) != AES.block_size:
        raise ValueError("Ciphertext length must be 16 bytes.")
    
    return AES.new(AES_KEY, AES.MODE_ECB).decrypt(ct)
        
def utc_timestamp() -> float:
    """Return current UTC time as POSIX timestamp (float)."""
    return datetime.now(tz=timezone.utc).timestamp()

def create_genesis_block() -> bytes:
    """
    Create the genesis block for the blockchain. Returns the exact 158-byte required by spec
    Bypasses the Block() class to avoid encryption on the case_id and evidence/item_id
    """
    prev_hash = b"\x00" * 32                # 32 bytes
    timestamp = utc_timestamp()             # 8‑byte float
    case_id   = b"0" * 32                   # 32 zeros
    item_id   = b"0" * 32                   # 32 zeros
    state     = b"INITIAL" + b"\x00" * 4    # 11 bytes (for some reason gradescope needs this???)
    creator   = b"\x00" * 12                # 12 null bytes
    owner     = b"\0" * 12                  # 12 null bytes
    d_length  = 14                          # 4 bytes
    data      = b"Initial block\x00"        # 14 bytes

    header = struct.pack(
        BLOCK_HEADER_FORMAT,
        prev_hash,
        timestamp,
        case_id,
        item_id,
        state,
        creator,
        owner,
        d_length
    )
    return header + data

# ---------------------------------------------------------------
# Block Class
# ---------------------------------------------------------------
class Block:
    """
    Represents a single block in the blockchain.
    """
    # ---------------------------------------------------------------
    # Construction helpers
    # ---------------------------------------------------------------
    def __init__(
            self, 
            prev_hash: bytes, 
            timestamp: float, 
            case_id, 
            evidence_id,
            state: str, 
            creator: str, 
            owner: str, 
            d_length: int, 
            data: str | bytes,
        ):
        """
        Create a new *in‑memory* block.  `case_id` and `evidence_id` are plaintext –
        they are encrypted inside the constructor so callers never deal with cipher text.
        `prev_hash` must already be a 32‑byte bytes object (sha‑256 digest).
        """
        self.prev_hash = prev_hash
        self.timestamp = timestamp

        # Normalise to raw 16‑byte UUID
        if isinstance(case_id, uuid.UUID):
            case_plain = case_id.bytes  # If it's a UUID, convert to 16 raw bytes
        elif isinstance(case_id, bytes):
            if len(case_id) == 16:
                case_plain = case_id    # Already 16 raw bytes
            else:
                case_plain = uuid.UUID(case_id.decode()).bytes
        elif isinstance(case_id, str):
            case_plain = uuid.UUID(case_id).bytes
        else:
            raise TypeError("case_id must be UUID/str/bytes")

        # evidence_id is a 4‑byte big endian int
        if isinstance(evidence_id, int):
            evidence_plain = struct.pack(">I", evidence_id)
        elif isinstance(evidence_id, bytes) and len(evidence_id) == 4:
            evidence_plain = evidence_id
        else:
            raise TypeError("evidence_id must be int or 4‑bytes")

        self.case_id_enc     = encrypt(case_plain)          # 32 bytes
        self.evidence_id_enc = encrypt_id(evidence_plain)   # 32 bytes
        # ---------------------------------------------------------------

        self.state = make_bytes(state).ljust(11, b'\0')
        self.creator = make_bytes(creator).ljust(12, b'\0')
        self.owner = make_bytes(owner).ljust(12, b'\0')
        self.d_length = d_length
        self.data = make_bytes(data)

    # ---------------------------------------------------------------
    # Serialisation helpers
    # ---------------------------------------------------------------
    def pack(self) -> bytes:
        """
        Pack the block into its on‑disk binary representation.
        """
        header = struct.pack(
            BLOCK_HEADER_FORMAT,
            self.prev_hash,
            self.timestamp,
            self.case_id_enc,
            self.evidence_id_enc,
            self.state,
            self.creator,
            self.owner,
            self.d_length,
        )
        return header + self.data

    # ---------------------------------------------------------------    
    # Alternate constructor – read from disk
    # ---------------------------------------------------------------
    @classmethod
    def unpack(cls, blob: bytes):
        """
        Create a Block instance from raw bytes read from disk.  Plaintext case_id and
        evidence_id are recovered via `decrypt`, so callers get the same interface
        as when they constructed the block themselves.
        """
        if len(blob) < HEADER_SIZE:
            raise ValueError("Blob too small to contain BCHOC block header")

        header = blob[:HEADER_SIZE]
        (prev_hash, timestamp, case_id_enc, evidence_id_enc,
         state, creator, owner, d_length) = struct.unpack(BLOCK_HEADER_FORMAT, header)

        expected_size = HEADER_SIZE + d_length
        if len(blob) < expected_size:
            raise ValueError("Blob truncated – declared data length exceeds blob size")

        data_bytes = blob[HEADER_SIZE:expected_size]

        evidence_id_raw=decrypt(evidence_id_enc)
        evidence_id_raw4 = evidence_id_raw[-4:]  # Keep the actual ID portion

        # Build a new Block with decrypted IDs
        return cls(
            prev_hash=prev_hash,
            timestamp=timestamp,
            case_id=decrypt(case_id_enc),
            evidence_id=evidence_id_raw4,
            state=state.rstrip(b"\0").decode(),
            creator=creator.rstrip(b"\0").decode(),
            owner=owner.rstrip(b"\0").decode(),
            d_length=d_length,
            data=data_bytes.decode(),
        )

    # ---------------------------------------------------------------
    # Convenience accessors
    # ---------------------------------------------------------------
    def iso_timestamp(self) -> str:
        """
        Return the stored timestamp in RFC‑3339/ISO‑8601 format (UTC).
        """
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat().replace("+00:00", "Z")

    def __repr__(self):
        state_str = self.state.rstrip(b'\x00').decode()
        case_str = decrypt(self.case_id_enc)
        item_str = decrypt(self.evidence_id_enc)
        return (
            f"\n******** BLOCK ********\n"
            f"time  = {self.iso_timestamp()}\n"
            f"state = {state_str}\n"
            f"case  = {case_str}\n"
            f"item  = {item_str}\n"
        )
    
    def print_block_bytes(self):
        """
        Debug helper to print out each field of the block in raw byte form along with length of field
        """
        # Timestamp and d_length are numeric so need to repack to get byte representations
        ts_bytes = struct.pack("d", self.timestamp)
        dlen_bytes = struct.pack("I", self.d_length)

        fields = [
            ("prev_hash", self.prev_hash.hex()),
            ("timestamp", ts_bytes),
            ("case_id_enc", self.case_id_enc),
            ("evidence_id_enc", self.evidence_id_enc),
            ("state", self.state),
            ("creator", self.creator),
            ("owner", self.owner),
            ("d_length", dlen_bytes),
            ("data", self.data),
        ]

        print("\n********   BLOCK   ********")
        for name, raw in fields:
            print(f"{name:15s} = {raw!r}   ({len(raw)} bytes)")
