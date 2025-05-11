from block import *
import os, hashlib, struct, uuid

"""
blockchain.py handles the functionality for interacting with the blockchain
"""

# Get the binary file, use a default if not found
BLOCKCHAIN_FILE = os.getenv("BCHOC_FILE_PATH", "blockchain.dat")

# Map valid creators to required passwords (as env vars) per assn spec
PASSWORD_MAP = {
    "Police": os.getenv("BCHOC_PASSWORD_POLICE"),
    "Lawyer": os.getenv("BCHOC_PASSWORD_LAWYER"),
    "Analyst": os.getenv("BCHOC_PASSWORD_ANALYST"),
    "Executive": os.getenv("BCHOC_PASSWORD_EXECUTIVE"),
    "Creator": os.getenv("BCHOC_PASSWORD_CREATOR")
}

REMOVAL_REASONS = ['DISPOSED', 'DESTROYED', 'RELEASED']

def is_valid_genesis_block(path):
    """
    Validates genesis block data
    """
    try:
        with open(path, 'rb') as f:
            header = f.read(HEADER_SIZE)

            if len(header) < HEADER_SIZE:
                return False
            
            # Extract d_len from the Block 
            *_, d_len,= struct.unpack(BLOCK_HEADER_FORMAT, header)

            if d_len != 14:
                print(f"d_len mismatch: {d_len}")
                return False
            
            # Valid genesis block will have 'Initial block\x00' in its data field
            data = f.read(d_len)
            return data == b"Initial block\x00"

    except OSError:
        return False

def is_valid_owner_password(password):
    """
    Determine if a password belongs to any of the owners
    """
    return password in PASSWORD_MAP.values()

def is_valid_creator_password(password):
    """
    Determines if provided password matches the creator's password
    """
    return password == os.getenv("BCHOC_PASSWORD_CREATOR")

def walk_blocks(path=BLOCKCHAIN_FILE):
    """
    Generator function to walk the blockchain from first to last block.
    Yields raw block data as well as the unpacked Block 
    """
    with open(path, 'rb') as f:
        first = True

        while True:
            header = f.read(HEADER_SIZE)
            if not header:
                break

            if len(header) < HEADER_SIZE:
                raise SystemExit("ERROR: Header size incorrect")
            
            # d_length is the final field in the header
            *_, d_len = struct.unpack(BLOCK_HEADER_FORMAT, header)            
            data = f.read(d_len)

            if len(data) < d_len:
                break
            
            block_data = header + data

            # If it's the genesis block, dont unpack the data since it is not of class Block
            if first:
                yield block_data, None
                first = False
            else:
                yield block_data, Block.unpack(block_data)

def add(case_id, item_id, creator, password):
    """
    Adds a new evidence item to the blockchain and associates it with the given case identifier.
    """
    # Ensure the password matches the creator password
    if not is_valid_creator_password(password):
        print("Error: Invalid password. Try again.")
        exit(1)
    
    # If no binary blockchain file, call init to create one
    if not os.path.exists(BLOCKCHAIN_FILE):
        init()

    # If invalid genesis block, error and exit
    if not is_valid_genesis_block(BLOCKCHAIN_FILE):
        print("ERROR: Invalid genesis block")
        exit(1)
    
    last_raw = None # Block iterator to be used in traversing the blockchain

    # Traverse each block in the blockchain
    for raw_data, block in walk_blocks():
        # If on genesis block, skip the uniqueness check since unencrypted 0 vals for item_id
        if block is None:
            last_raw = raw_data
            continue

        last_raw = raw_data

        # If item id is not unique, exit with error code
        evidence_id_raw = decrypt(block.evidence_id_enc)[-4:]
        evidence_id = int.from_bytes(evidence_id_raw, "big")
        if evidence_id == item_id:
            print("ERROR: item ID is not unique.")
            exit(1)

    if last_raw is None:
        prev_hash = b'\x00'*32  # First link's prev_hash is all zeroes for the genesis block
    else:
        prev_hash = hashlib.sha256(last_raw).digest()

    # Make the new block
    new_block = Block(
        prev_hash=prev_hash,
        timestamp=utc_timestamp(),
        case_id=case_id,        # uuid.UUID instance
        evidence_id=item_id,    # int
        state="CHECKEDIN",
        creator=creator,
        owner=b'\0'*12,
        d_length=0,
        data=b""
    )

    # Append new block to the blockchain
    with open(BLOCKCHAIN_FILE, 'ab') as f:
        f.write(new_block.pack())

    # Get new state to avoid f-string expression issues
    new_state = new_block.state.rstrip(b'\0').decode()

    print(f"Added item: {item_id}")
    print(f"Status: {new_state}")
    print(f"Time of action: {new_block.iso_timestamp()}")

def checkout(item_id, password):
    """
    Adds a new checkout entry to the chain of custody for the given evidence item.
    """
    # Ensure password is an owner password
    if not is_valid_owner_password(password):
        print("ERROR: Invalid password.")
        exit(1)

    found_match = False # Flag to track when we've found a matching item_id
    last_raw = None     # Iterator to be used when traversing the blockchain
    new_owner = None

    # Ensure item_id is already in the blockchain
    for raw_data, block in walk_blocks():
        # If on genesis block, skip since no item_id
        if block is None:
            continue

        # Search for a matching item_id in the blockchain
        evidence_id_raw = decrypt(block.evidence_id_enc)[-4:]
        evidence_id = int.from_bytes(evidence_id_raw, "big")
        if evidence_id == item_id:
            raw_case = decrypt(block.case_id_enc)
            parent_case_id = uuid.UUID(bytes=raw_case)
            parent_state = block.state
            parent_creator = block.creator
            last_raw = raw_data
            found_match = True

    # If the last block was the genesis block, nothing to checkout
    if last_raw == None:
        print("ERROR: No items to checkout")
        exit(1)

    if not found_match:
        print("ERROR: Item does not exist")
        exit(1)

    printable_state = parent_state.strip(b'\x00').decode()

    if printable_state == "CHECKEDOUT":
        print("ERROR: Item is already checked out")
        exit(1)

    if printable_state in REMOVAL_REASONS:
        print("ERROR: Item has been removed")
        exit(1)

    # Find which owner the password belongs to
    for role, pw in PASSWORD_MAP.items():
        if pw == password:
            new_owner = role.upper()
            break
    
    # Make the new block
    new_block = Block(
        prev_hash=hashlib.sha256(last_raw).digest(),
        timestamp=utc_timestamp(),
        case_id=parent_case_id,
        evidence_id=item_id,
        state="CHECKEDOUT",
        creator=parent_creator,
        owner=new_owner,
        d_length=0,
        data=b""
    )

    new_state = new_block.state.strip(b'\x00').decode()

    # Append new block to the blockchain
    with open(BLOCKCHAIN_FILE, 'ab') as f:
        f.write(new_block.pack())

    print(f"Case: {parent_case_id}")
    print(f"Checked out item: {item_id}")
    print(f"Status: {new_state}")
    print(f"Time of action: {new_block.iso_timestamp()}")

def checkin(item_id, password):
    """
    Adds a new checkin entry to the chain of custody for the given evidence item
    """
    # Ensure password is an owner password
    if not is_valid_owner_password(password):
        print("ERROR: Invalid password.")
        exit(1)

    found_match = False # Flag to track when we've found a matching item_id
    last_raw = None     # Iterator to be used when traversing the blockchain
    new_owner = None

    # Ensure item_id is already in the blockchain
    for raw_data, block in walk_blocks():
        # If on genesis block, skip since no item_id
        if block is None:
            continue

        # Search for a matching item_id in the blockchain
        evidence_id_raw = decrypt(block.evidence_id_enc)[-4:]
        evidence_id = int.from_bytes(evidence_id_raw, "big")
        if evidence_id == item_id:
            raw_case = decrypt(block.case_id_enc)
            parent_case_id = uuid.UUID(bytes=raw_case)
            parent_state = block.state
            parent_creator = block.creator
            last_raw = raw_data
            found_match = True

    # If the last block was the genesis block, nothing to checkout
    if last_raw == None:
        print("ERROR: No items to checkout")
        exit(1)

    if not found_match:
        print("ERROR: Item does not exist")
        exit(1)
    
    printable_state = parent_state.strip(b'\x00').decode()

    if printable_state == "CHECKEDIN":
        print("ERROR: Item is already checked in")
        exit(1)

    if printable_state in REMOVAL_REASONS:
        print("ERROR: Item has been removed")
        exit(1)

    # Find which owner the password belongs to
    for role, pw in PASSWORD_MAP.items():
        if pw == password:
            new_owner = role.upper()
            break
    
    # Make the new block
    new_block = Block(
        prev_hash=hashlib.sha256(last_raw).digest(),
        timestamp=utc_timestamp(),
        case_id=parent_case_id,
        evidence_id=item_id,
        state="CHECKEDIN",
        creator=parent_creator,
        owner=new_owner,
        d_length=0,
        data=b""
    )

    new_state = new_block.state.strip(b'\x00').decode()

    # Append new block to the blockchain
    with open(BLOCKCHAIN_FILE, 'ab') as f:
        f.write(new_block.pack())

    print(f"Case: {parent_case_id}")
    print(f"Checked in item: {item_id}")
    print(f"Status: {new_state}")
    print(f"Time of action: {new_block.iso_timestamp()}")

def show_cases():
    """
    Displays a list of all the cases that have been added to the blockchain
    """
    case_ids = set()

    # Traverse each block in the blockchain
    for _, block in walk_blocks():
        # Skip the genesis block since no case_id
        if block is None:
            continue

        try:
            raw_case = decrypt(block.case_id_enc)
            if len(raw_case) != 16:
                raise ValueError(f"Decrypted case_id is not 16 bytes: {raw_case.hex()}")

            case_id = uuid.UUID(bytes=raw_case)
            case_ids.add(case_id)
        except Exception as e:
            print(f"WARNING: Skipping malformed block: {e}")

    for case_id in case_ids:
        print(str(case_id))

def show_items(case_id):
    """
    Displays all the items corresponding to the case number in the request
    """
    item_ids = set()    # Use a set to track unique item IDs
    
    # Traverse each block in the blockchain
    for raw_data, block in walk_blocks():
        # If on genesis block, skip
        if block is None:
            continue

        block_case_id_raw = decrypt(block.case_id_enc)
        block_case_id = uuid.UUID(bytes=block_case_id_raw)

        # If case IDs match
        if block_case_id == case_id:
            # Extract the item id and the status
            item_id = int.from_bytes(decrypt(block.evidence_id_enc)[-4:], "big")
            item_ids.add(item_id)

    for item in item_ids:
        print(str(item))
            
def show_history(case_id, item_id, num_entries, reverse, password):
    """
    Displays the blockchain entries for the requested item giving the oldest first
    
    Args:
        - case_id (uuid or None): when used, only blocks with given case id displayed
        - item_id (int or None): when used, only blocks with given item id displayed
        - num_entries (int or None): shows num_entries number of blocks
        - reverse (bool): if True, most recent blocks displayed first. False = oldest first
        - password (str): must match any of the owner's passwords
    """
    # Ensure password is an owner password
    if not is_valid_owner_password(password):
        print("ERROR: Invalid password.")
        exit(1)

    block_entries = []  # List to tuple of block details
                        # (case_id, item_id, state_str, timestamp, formatted timestamp)

    for raw_data, block in walk_blocks():
        # Genesis block
        if block is None:
            # Extract necessary info from the block
            _, ts, _, _, state_bytes, _, _, _ = struct.unpack(BLOCK_HEADER_FORMAT, raw_data[:HEADER_SIZE])
            
            # Genesis block isn't encrypted, just raw byte values
            block_case_id = uuid.UUID(int=0)
            block_item_id = 0
            block_state = state_bytes.strip(b'\x00').decode()
            block_ts = 0
            block_time = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            block_case_id = uuid.UUID(bytes=decrypt(block.case_id_enc))
            block_item_id = int.from_bytes(decrypt(block.evidence_id_enc)[-4:], 'big')
            block_state = block.state.strip(b'\x00').decode()
            block_ts = block.timestamp
            block_time = block.iso_timestamp()

        # Filter by the case_id, if provided
        if case_id is not None and block_case_id != case_id:
            continue

        # Filter by item_id, if provided
        if item_id is not None and block_item_id != item_id:
            continue

        block_entries.append((block_case_id, block_item_id, block_state, block_ts, block_time))

    if not block_entries:
        return

    # Sort the blocks by timestamp depending if reverse is True or False
    block_entries.sort(key=lambda t: t[3], reverse=reverse)

    # Only print out num_entries blocks
    if num_entries is not None:
        block_entries = block_entries[:num_entries]

    for case, item, state, _, time in block_entries:
        print(f"Case: {case}")
        print(f"Item: {item}")
        print(f"Action: {state}")
        print(f"Time: {time}\n")  # Formatted timestamp

def remove(item_id, reason, password):
    """
    Prevents any further action from being taken on the evidence item specified
    """
    # Ensure the password matches the creator password
    if not is_valid_creator_password(password):
        print("ERROR: Invalid password")
        exit(1)

    found_match = False # Flag to track when we've found a matching item_id
    last_raw = None     # Iterator to be used when traversing the blockchain
    item_raw = None

    # Ensure item_id is in the blockchain
    for raw_data, block in walk_blocks():
        # If on genesis block, skip since no item_id
        if block is None:
            continue

        last_raw = raw_data

        # Search for a matching item_id in the blockchain
        evidence_id_raw = decrypt(block.evidence_id_enc)[-4:]
        evidence_id = int.from_bytes(evidence_id_raw, "big")
        if evidence_id == item_id:
            item_raw = raw_data
            raw_case = decrypt(block.case_id_enc)
            parent_case_id = uuid.UUID(bytes=raw_case)
            parent_state = block.state
            parent_creator = block.creator
            parent_owner = block.owner

    # If the last block was the genesis block, nothing to checkout
    if last_raw is None:
        print("ERROR: No items to remove")
        exit(1)

    if item_raw is None:
        print("ERROR: Item does not exist")
        exit(1)
    
    printable_state = parent_state.strip(b'\x00').decode()

    if printable_state != "CHECKEDIN":
        print("ERROR: Item must be checked in before removal")
        exit(1)
    
    # Make the new block
    new_block = Block(
        prev_hash=hashlib.sha256(last_raw).digest(),
        timestamp=utc_timestamp(),
        case_id=parent_case_id,
        evidence_id=item_id,
        state=reason,
        creator=parent_creator,
        owner=parent_owner,
        d_length=0,
        data=b""
    )

    new_state = new_block.state.strip(b'\x00').decode()

    # Append new block to the blockchain
    with open(BLOCKCHAIN_FILE, 'ab') as f:
        f.write(new_block.pack())

    print(f"Case: {parent_case_id}")
    print(f"Removed item: {item_id}")
    print(f"Status: {new_state}")
    print(f"Time of action: {new_block.iso_timestamp()}")

def init(args=None):
    """
    Ensure presence of the genesis block in the blockchain.
    When called for the first time, verify if a blockchain binary file exists.
    If no file found, create one and insert the Genesis block. For subsequent
    calls, check for existence of both blockchain file AND genesis block
    """    
    # If no file found, create one and insert the genesis block with below info
    if not os.path.exists(BLOCKCHAIN_FILE):
        # Create the genesis block
        genesis_block = create_genesis_block()

        # Open the blockchain file and write the block to the file
        with open(BLOCKCHAIN_FILE, 'wb') as f:
            f.write(genesis_block)
        
        print("Blockchain file not found. Created INITIAL block.")
    else:
        # If a valid file WAS found, check to make sure the genesis block is valid
        if is_valid_genesis_block(BLOCKCHAIN_FILE):
            print("Blockchain file found with INITIAL block.")
        else:
            print("ERROR: Invalid genesis block")
            exit(1)

def verify():
    """
    Parses the blockchain and validates all entries
    """
    # Check if genesis block is valid, exit with error code if not
    if not is_valid_genesis_block(BLOCKCHAIN_FILE):
        print("ERROR: Invalid genesis block")
        exit(1)

    block_digests: dict[bytes, bytes] = {}  # Store block digests to compute checksums
    block_parents: dict[bytes, bytes] = {}  # Stores parent-child relationships
    block_items_states: dict[int, str] = {} # Stores most recent state for each item id

    seen_blocks = 0
    bad_block_digest: bytes | None = None 
    error_msg = ""

    # Traverse each block in the blockchain
    for index, (raw_data, block) in enumerate(walk_blocks()):
        digest = hashlib.sha256(raw_data).digest()   # Compute SHA-256 digest for block
        block_digests[digest] = raw_data

        # Skip genesis block
        if index == 0:
            continue

        seen_blocks += 1
        
        parent = block.prev_hash

        # 1st check - make sure parent is *before* this block
        if parent not in block_digests:
            bad_block_digest = digest
            error_msg = "Parent block: NOT FOUND"
            break

        # 2nd check - parent can only have one child
        if parent in block_parents:                 # If already a parent
            other_child = block_parents[parent]     # Extract the other child

            # If they are not equal, then two blocks have the same parent 
            if other_child != digest:
                bad_block_digest = digest
                error_msg = (   # Attempting to match gradescope/spec formatting
                    "Parent block:\n"
                    f"{parent.hex()}\n"
                    "Two blocks were found with the same parent."
                )
                break

        # Parent has no other children - record parent-child relationship in the list
        else:
            block_parents.setdefault(parent, digest)

        # 3rd check - parent hash must equal the SHA-256 checksum
        expected_parent_digest = hashlib.sha256(block_digests[parent]).digest()
        if parent != expected_parent_digest:
            bad_block_digest = digest
            error_msg = "Block contents do not match block checksum."
            break

        # 4th check - block state checks, can't have checkin/checkout after removal reasons
        item_id = int.from_bytes(decrypt(block.evidence_id_enc)[-4:], "big")
        state = block.state.strip(b'\x00').decode()

        if (item_id in block_items_states                       # If we've already seen the item
            and block_items_states[item_id] in REMOVAL_REASONS  # and previous reason was a removal reason
            and state in {"CHECKEDIN", "CHECKEDOUT"}            # and we are now trying to use it again
        ):
            bad_block_digest = digest
            error_msg = "Item checked out or checked in after removal from chain."
            break
        
        # 5th check - double checkin/checkout/removal
        if (item_id in block_items_states               # If we've already seen the item
            and block_items_states[item_id] == state):  # and previous reason == new reason
            bad_block_digest = digest
            error_msg = "Double checkin/checkout/removal detected."
            break
        
        # Record the latest state for this item
        block_items_states[item_id] = state


    print(f"Transactions in blockchain: {seen_blocks}")

    # If no errors
    if bad_block_digest is None:
        print("State of blockchain: CLEAN")
        return 0

    # Print error details
    print("State of blockchain: ERROR")
    print("Bad block:")
    print(bad_block_digest.hex())
    print(error_msg)
    exit(1)

def summarize(case_id):
    """
    Iterate through the blocks and print the number of unique item IDs, num blocks
    in CHECKEDIN, CHECKEDOUT, DISPOSED, DESTROYED, and RELEASED, Takes case_id as input
    """
    seen_ids = set()    # Use a set to track unique item IDs
    total_items = 0
    total_checkedin = 0
    total_checkedout = 0
    total_disposed = 0
    total_destroyed = 0
    total_released = 0

    # Traverse each block in the blockchain
    for raw_data, block in walk_blocks():
        # If on genesis block, skip
        if block is None:
            continue

        # Get the 4-byte item ID
        item_id = int.from_bytes(decrypt(block.evidence_id_enc)[-4:], "big")

        block_state = block.state.strip(b'\x00').decode()

        match block_state:
            case 'CHECKEDIN':
                seen_ids.add(item_id)
                total_checkedin += 1
            case 'CHECKEDOUT':
                total_checkedout += 1
            case 'DISPOSED':
                total_disposed += 1
            case 'DESTROYED':
                total_destroyed += 1
            case 'RELEASED':
                total_released += 1
            case _:
                raise ValueError("ERROR: State not recognized")
            
    total_items = len(seen_ids)

    print(f'Case Summary for Case ID: {case_id}')
    print(f'Total Evidence Items: {total_items}')
    print(f'Checked In: {total_checkedin}')
    print(f'Checked Out: {total_checkedout}')
    print(f'Disposed: {total_disposed}')
    print(f'Destroyed: {total_destroyed}')
    print(f'Released: {total_released}')