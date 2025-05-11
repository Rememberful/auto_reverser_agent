import subprocess
import re
import os

# Function to extract strings from a binary file
def extract_strings(file_path):
    print("[*] Extracting strings...")
    try:
        # Running the strings command
        result = subprocess.run(['strings', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        strings_output = result.stdout
        # Searching for suspicious patterns (URLs, IPs, file paths, etc.)
        suspicious_patterns = []
        patterns = [
            r'(https?://[^\s]+)',  # URLs
            r'(\d+\.\d+\.\d+\.\d+)',  # IP addresses
            r'([a-zA-Z0-9_\\/-]+(?:\.exe|\.dll|\.bat))',  # File paths
            r'([a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+)'  # Email addresses
        ]
        
        for pattern in patterns:
            suspicious_patterns.extend(re.findall(pattern, strings_output))

        # Print the suspicious patterns found
        if suspicious_patterns:
            print("[*] Suspicious patterns found in strings:")
            for match in suspicious_patterns:
                print(f"    {match}")
        else:
            print("[*] No suspicious patterns found in strings.")
        
        return strings_output

    except Exception as e:
        print(f"Error extracting strings: {e}")
        return None

# Function to disassemble the binary file using radare2
def disassemble_binary(file_path):
    print("[*] Extracting disassembly...")
    try:
        # Running radare2 for disassembly extraction
        result = subprocess.run(['radare2', '-c', 'pd 20', '-q', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        disassembly_output = result.stdout
        # Looking for suspicious disassembly patterns (e.g., calls to API functions)
        suspicious_disassembly = []
        if disassembly_output:
            # Check for known malicious API calls or suspicious jumps (e.g., `jmp`, `call`)
            suspicious_disassembly.extend(re.findall(r'\b(jmp|call)\b.*', disassembly_output))

        # Print suspicious disassembly patterns
        if suspicious_disassembly:
            print("[*] Suspicious disassembly patterns found:")
            for line in suspicious_disassembly:
                print(f"    {line}")
        else:
            print("[*] No suspicious disassembly patterns found.")
        
        return disassembly_output

    except Exception as e:
        print(f"Error extracting disassembly: {e}")
        return None

# Main function to analyze the binary
def analyze_binary(file_path):
    # Extract strings from the binary
    strings_output = extract_strings(file_path)
    # Disassemble the binary to extract function calls and instructions
    disassembly_output = disassemble_binary(file_path)

    # You can add more analysis here if needed, e.g., analyzing specific sections of the binary
    # Output results or further processing
    return strings_output, disassembly_output

# Entry point for the script
if __name__ == "__main__":
    file_path = input("Enter the file path for analysis: ").strip()
    
    if os.path.exists(file_path):
        print(f"[*] Analyzing: {file_path}")
        analyze_binary(file_path)
    else:
        print(f"Error: File {file_path} does not exist.")
