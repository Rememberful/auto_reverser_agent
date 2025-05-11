import subprocess
import os
from metadata_extractor import analyze_pe_file

def extract_strings(file_path):
    """Extract strings from a binary file using the 'strings' command."""
    result = subprocess.run(['strings', file_path], capture_output=True, text=True)
    return result.stdout

def extract_disassembly(file_path):
    """Extract disassembly from a binary file using 'objdump'."""
    result = subprocess.run(['objdump', '-d', file_path], capture_output=True, text=True)
    return result.stdout

def analyze_binary(file_path):
    """Perform basic static analysis on a binary file."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file {file_path} does not exist.")
    
    # Run the enhanced metadata analysis
    metadata_analysis = analyze_pe_file(file_path)

    # Run other static analysis functions (strings, disassembly)
    strings = extract_strings(file_path)
    disassembly = extract_disassembly(file_path)
    
    analysis_result = {
        'metadata': metadata_analysis,
        'strings': strings,
        'disassembly': disassembly
    }
    
    return analysis_result
