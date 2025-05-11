#!/usr/bin/env python3

from cli import *

def main():
    args = parse_arguments()
    args.func(args)

if __name__ == '__main__':
    main()