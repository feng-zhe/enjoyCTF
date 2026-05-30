#!/usr/bin/env python3
import sys
from itertools import zip_longest

def compare_files(filenames):
    if not filenames:
        print("Error: No files provided.", file=sys.stderr)
        return

    try:
        # Open all files simultaneously
        files = [open(f, 'r', encoding='utf-8') for f in filenames]
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return

    print(f"--- Comparing {len(filenames)} files line-by-line ---")
    
    try:
        # zip_longest allows us to iterate line-by-line across all files, 
        # filling with None if one file is shorter than the others.
        for line_num, lines in enumerate(zip_longest(*files), start=1):
            
            # If any file has already run out of lines, we can't compare anymore
            if any(line is None for line in lines):
                break
            
            # Strip trailing newlines/whitespace to properly check the last 5 characters
            stripped_lines = [line.rstrip('\r\n') for line in lines]
            
            # Condition 1: Ensure every line is at least 5 characters long
            if any(len(line) < 5 for line in stripped_lines):
                continue
                
            # Condition 2: Check if the last 5 characters match across ALL files
            first_suffix = stripped_lines[0][-5:]
            if all(line[-5:] == first_suffix for line in stripped_lines):
                # Concatenate the stripped line contents together
                concatenated_output = "".join(stripped_lines)
                print(f"{concatenated_output}")
                
    finally:
        # Ensure all file descriptors are closed safely
        for f in files:
            f.close()

if __name__ == "__main__":
    # Ensure at least one filename is passed via command line
    if len(sys.argv) < 2:
        print("Usage: python3 compare_files.py <file1> <file2> [file3 ...]", file=sys.stderr)
        sys.exit(1)
        
    compare_files(sys.argv[1:])
