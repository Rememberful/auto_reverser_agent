# main.py - Enhanced for debugging and visible output
import sys
from interface.cli import main

if __name__ == "__main__":
    try:
        print("[*] Starting Auto Reverser Agent...")
        main()
        print("[*] Analysis completed.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")
        import traceback
        traceback.print_exc()
