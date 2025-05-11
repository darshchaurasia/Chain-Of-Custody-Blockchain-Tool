"""
cli.py handles the command line interaction for the program,
validates user-provided input,
"""

import argparse
import uuid
from block import *
from blockchain import *

def validate_uuid(value: str) -> uuid.UUID:
    """
    Removes hyphens from a plaintext string, checks if valid UUID, then returns it or raises
    """
    hex_str = value.replace("-", "")
    
    if len(hex_str) != 32:
        raise argparse.ArgumentTypeError(f"ERROR: Invalid UUID length: {hex_str}, len: {len(hex_str)}")
    
    try:
        # Check if the parsed UUID is a valid UUID, return it if so
        return uuid.UUID(hex=hex_str)
    except ValueError:
        raise argparse.ArgumentTypeError("ERROR: Invalid UUID")
    
def validate_reason(value: str) -> str:
    """
    Ensures reason for removal is a valid reason
    """
    if value not in REMOVAL_REASONS:
        print("ERROR: Invalid reason for removal. Must be DISPOSED, DESTROYED, or RELEASED")
        exit(1)
    else:
        return value

# Utility functions that call their respective handlers in blockchain.py
def handle_add_cmd(args):
    for item in args.item_id:
        add(args.case_id, item, args.creator, args.password)

def handle_checkout_cmd(args):
    checkout(args.item_id, args.password)

def handle_checkin_cmd(args):
    checkin(args.item_id, args.password)

def handle_show_cases_cmd(args):
    show_cases()

def handle_show_items_cmd(args):
    show_items(args.case_id)

def handle_show_history_cmd(args):
    show_history(
        case_id=args.case_id,
        item_id=args.item_id,
        num_entries=args.num_entries,
        reverse=args.reverse,
        password=args.password
    )

def handle_remove_cmd(args):
    remove(
        args.item_id,
        args.why,
        args.password
    )

def handle_init_cmd(args):
    init()

def handle_verify_cmd(args):
    verify()

def handle_summary_cmd(args):
    summarize(args.case_id)

def init_parser():
    parser = argparse.ArgumentParser(
        prog="bchoc",
        description="Functions as a digital version of a chain of custody form"
    )

    subparsers = parser.add_subparsers(
        title="Available Commands",
        dest="command", # Store in args.command
    )

    # Add
    parser_add = subparsers.add_parser('add', help="Add a new evidence item to the blockchain and associate it with the given case identifier")
    parser_add.add_argument('-c', '--case_id', required=True, type=validate_uuid, help="Case identifier (UUID)")
    parser_add.add_argument('-i', '--item_id', required=True, action='append', type=int, help="One or more evidence item identifiers")
    parser_add.add_argument('-g', '--creator', required=True, help="Creator designation")
    parser_add.add_argument('-p', '--password', required=True, help="Creator's password")
    parser_add.set_defaults(func=handle_add_cmd)

    # Checkout
    parser_checkout = subparsers.add_parser('checkout', help="Add a new checkout entry to the chain of custody for the given evidence item")
    parser_checkout.add_argument('-i', '--item_id', required=True, type=int, help="Specifies the evidence item’s identifier (4-byte integer)")
    parser_checkout.add_argument('-p', '--password', required=True, help="Creator's password")
    parser_checkout.set_defaults(func=handle_checkout_cmd)

    # Checkin
    parser_checkin = subparsers.add_parser('checkin', help="Add a new checkin entry to the chain of custody for the given evidence item")
    parser_checkin.add_argument('-i', '--item_id', required=True, type=int, help="Specifies the evidence item’s identifier (4-byte integer)")
    parser_checkin.add_argument('-p', '--password', required=True, help="Creator's password")
    parser_checkin.set_defaults(func=handle_checkin_cmd)

    # Show
    parser_show = subparsers.add_parser('show', help="show cases, show items, or show history")
    subparsers_show = parser_show.add_subparsers(dest="show_subcommand")    # Add a separate subparser to the show subparser

    # Show cases
    parser_show_cases = subparsers_show.add_parser('cases', help="Display a list of all the cases that have been added to the blockchain")
    parser_show_cases.set_defaults(func=handle_show_cases_cmd)

    # Show items
    parser_show_items = subparsers_show.add_parser('items', help="Display all the items corresponding to the case number in the request")
    parser_show_items.add_argument('-c', '--case_id', type=validate_uuid, required=True, help="Case ID (UUID)")
    parser_show_items.set_defaults(func=handle_show_items_cmd)

    # Show history
    parser_show_history = subparsers_show.add_parser('history', help="Display the blockchain entries for the requested item giving the oldest first")
    parser_show_history.add_argument('-c', '--case_id', type=validate_uuid, help="Case ID (UUID)")
    parser_show_history.add_argument('-i', '--item_id', type=int, help="Evidence item ID")
    parser_show_history.add_argument('-n', '--num_entries', type=int, help="Number of entries to display")
    parser_show_history.add_argument('-r', '--reverse', action='store_true', help="Show most recent first") # Use action='store_true' to act as a boolean flag. If user includes -r, true, else false
    parser_show_history.add_argument('-p', '--password', required=True, help="Creator's password")
    parser_show_history.set_defaults(func=handle_show_history_cmd)

    # Remove
    parser_remove = subparsers.add_parser('remove', help="Prevents any further action from being taken on the evidence item specified")
    parser_remove.add_argument('-i', '--item_id', required=True, type=int, help="Evidence item ID")
    parser_remove.add_argument('-y', '--why', required=True, type=validate_reason, help="Reason for removal (DISPOSED, DESTROYED, or RELEASED)")
    parser_remove.add_argument('-p', '--password', required=True, help="Creator's password")
    parser_remove.set_defaults(func=handle_remove_cmd)

    # Init
    parser_init = subparsers.add_parser('init', help="Initialize the blockchain")
    parser_init.set_defaults(func=handle_init_cmd)

    # Verify
    parser_verify = subparsers.add_parser('verify', help="Parse the blockchain and validate all entries")
    parser_verify.set_defaults(func=handle_verify_cmd)

    # Summary
    parser_summary = subparsers.add_parser('summary', help="Summarize blockchain data")
    parser_summary.add_argument('-c', '--case_id', type=validate_uuid, required=True, help="Case ID (UUID)")
    parser_summary.set_defaults(func=handle_summary_cmd)

    return parser

def parse_arguments():
    parser = init_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        exit(1)

    return args