# Blockchain – Chain of Custody
## Python - Programming Language-Based*

**Stephanie Uriostegui Fernandez**  
**Kevin Johnston**  
**Rayan Alasow**  
**Darsh Chaurasia**  

---
## Overview
This project creates a blockchain — a secure and transparent system that can be used to maintain the integrity of digital evidence records, that stores each entry in a *Chain of Custody*. A Chain of Custody form keeps track of three pieces of important information (in addition to all the details that uniquely identify the specific piece of evidence):
1. Where the evidence was stored?  
2. Who had access to the evidence and when?  
3. What actions were taken to the evidence?  

## Project Files
1. `Makefile`:
2. `blockchain.py`:
3. `block.py`:
4. `bchoc.py`

## Building and Running the Project  
### Prerequisites
1. Ubuntu 18.04 64-bit with the default packages installed
2. Python 3.12.3 or lastest
3. Project program files: `Makefile`, `blockchain.py`, `block.py`, and `bchoc.py`

### 1. Build the Project   
Once all prerequisites are satisfied, run the `make` command in your ubuntu environment to create `bchoc`

    Group 18$ make
    cp bchoc.py bchoc
    chmod +x bchoc


### Arguments
| Parameters | Specifications |
| --- | --- |
| -c case_id | Specifies the case identifier that the evidence is associated with. Must be a valid UUID. When used with show only blocks with the given case_id are returned. |
| -i item_id | Specifies the evidence item’s identifier. When used with show  only blocks with the given item_id are returned. The item ID must be unique within the blockchain. This means you cannot re-add an evidence item once the remove action has been performed on it. |
| -p password | Has to be one of the creators or owners. The passwords will be provided to you. |
| -n num_entries | When used with history, shows num_entries number of block entries. |
| -r, –reverse | When used with history, reverses the order of the block entries to show the most recent entries first. |
| -y reason, --why reason |  Reason for the removal of the evidence item. Must be one of: DISPOSED, DESTROYED, or RELEASED. If the reason given is RELEASED, -o must also be given. |
| -o owner | Information about the lawful owner to whom the evidence was released. At this time, text is free-form and does not have any requirements. |
| -g --creator | Specifies the creator of the evidence item. |


## 2. Managing Evidence Items

### Add Evidence (`add`)

Add one or more new evidence items to the blockchain under a specified case ID. The initial state of each item is `CHECKEDIN`. The evidence ID must be unique.

> Requires: Creator password

```bash
bchoc add -c case_id -i item_id [-i item_id ...] -g creator -p password

```

### Remove Evidence (`remove`)

Mark an evidence item as inactive. No further actions can be taken on it. The item must be in the `CHECKEDIN` state.

> Requires: Creator password

```bash
bchoc remove -i item_id -y reason -p password

```

## 3. Chain of Custody Operations

### Check Out Evidence (`checkout`)

Create a checkout record for an existing evidence item.

> Requires: Owner password

```bash
bchoc checkout -i item_id -p password

```

### Check In Evidence (`checkin`)

Create a checkin record for an existing evidence item.

> Requires: Owner password

```bash
bchoc checkin -i item_id -p password

```

## 4. Viewing Records

### Show All Cases (`show cases`)

List all case IDs that have been added to the blockchain.

> Requires: Owner password

```bash
bchoc show cases

```

### Show Evidence Items (`show items`)

List all evidence items associated with a specific case ID.

> Requires: Owner password

```bash
bchoc show items -c case_id

```

### Show Evidence History (`show history`)

Display the chain of custody for a given evidence item. Results are shown oldest-to-newest unless `--reverse` is specified.

> Requires: Owner password

```bash
bchoc show history [-c case_id] [-i item_id] [-n num_entries] [-r] -p password

```

## 5. Blockchain Utilities

### Initialize Blockchain (`init`)

Perform a sanity check and initialize the blockchain if necessary.

```bash
bchoc init

```

### Verify Blockchain Integrity (`verify`)

Scan and verify all entries in the blockchain for integrity and consistency.

```bash
bchoc verify

```

## 6. Summary Statistics

### Summary Report (`summary`)

Print a summary of evidence states and counts for a given case ID. Includes the number of unique item IDs and how many are currently in each state (`CHECKEDIN`, `CHECKEDOUT`, `DISPOSED`, `DESTROYED`, `RELEASED`).

> Requires: Owner password

```bash
bchoc summary -c case_id

```


## Description  
  - bchoc functions as a digital version of a chain of custody form by utiliz-
    ing a blockchain to store evidence items. At a high level, the program
    parses arguments provided by the user via command-line and then calls the
    appropriate functions to perform the requested actions. As a chain of cus-
    tody form, our program is capable of managing evidence-related actions,
    such as checking-in, checking-out, disposing, destroying, and releasing
    evidence. Additionally, our program can show all cases and items currently
    in the blockchain, and can filter based on case ID and item ID. The verify
    function checks every block in the blockchain for errors to maintain inte-
    grity of the chain. We have also incorporated robust error-handling in the
    program to account for invalid inputs and cases which may cause failure.
