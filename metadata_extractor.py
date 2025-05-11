import pefile
import struct

def extract_metadata(file_path):
    """Extract metadata (e.g., headers) from a binary using 'pefile'."""
    pe = pefile.PE(file_path)

    # Extract basic metadata
    arch = pe.FILE_HEADER.Machine
    os = 'windows'  # Since we are focusing on PE files, we assume Windows OS
    bits = '32-bit' if pe.FILE_HEADER.Machine == 0x14C else '64-bit'  # Check if 32-bit or 64-bit

    # Extract language if available
    lang_code = getattr(pe.FILE_HEADER, 'Language', None)  # Use getattr to avoid AttributeError
    lang = get_language_from_code(lang_code) if lang_code else 'Unknown'  # Map language code to name

    metadata = {
        'architecture': hex(arch),
        'os': os,
        'language': lang,
        'bits': bits
    }
    return metadata

def get_language_from_code(code):
    """Map the language code to a human-readable string."""
    language_map = {
        0x0400: "Chinese (Simplified)",
        0x0401: "Arabic",
        0x0402: "Bulgarian",
        0x0403: "Czech",
        0x0404: "Danish",
        0x0405: "Dutch",
        0x0406: "English",
        0x0407: "Estonian",
        0x0408: "Finnish",
        0x0409: "French",
        0x040a: "German",
        0x040b: "Greek",
        0x040c: "Hebrew",
        0x040d: "Hungarian",
        0x040e: "Icelandic",
        0x040f: "Italian",
        0x0410: "Japanese",
        0x0411: "Korean",
        0x0412: "Latvian",
        0x0413: "Lithuanian",
        0x0414: "Norwegian",
        0x0415: "Polish",
        0x0416: "Portuguese",
        0x0417: "Romanian",
        0x0418: "Russian",
        0x0419: "Serbian",
        0x041a: "Slovak",
        0x041b: "Slovenian",
        0x041c: "Spanish",
        0x041d: "Swedish",
        0x041e: "Thai",
        0x041f: "Turkish",
        0x0420: "Ukrainian",
        0x0421: "Greek",
        0x0800: "Vietnamese",
        0x0804: "Chinese (Traditional)"
    }
    
    return language_map.get(code, 'Unknown')  # Return 'Unknown' if code not found

def extract_pe_header(file_path):
    """Inspect the PE header for additional details."""
    pe = pefile.PE(file_path)

    pe_header_info = {
        'signature': hex(pe.DOS_HEADER.e_magic),  # Signature of the PE file (should be '0x5A4D' for DOS header)
        'machine': hex(pe.FILE_HEADER.Machine),  # The target machine type (e.g., x86)
        'timestamp': pe.FILE_HEADER.TimeDateStamp,  # Timestamp when the file was created
        'number_of_sections': pe.FILE_HEADER.NumberOfSections,  # Number of sections in the PE file
    }

    return pe_header_info

def extract_section_headers(file_path):
    """Extract section headers from the PE file."""
    pe = pefile.PE(file_path)
    sections = []

    for section in pe.sections:
        section_info = {
            'name': section.Name.decode().strip(),
            'virtual_address': hex(section.VirtualAddress),
            'virtual_size': hex(section.Misc_VirtualSize),
            'raw_size': hex(section.SizeOfRawData),
            'characteristics': hex(section.Characteristics),
        }
        sections.append(section_info)

    return sections

def analyze_pe_file(file_path):
    """Perform enhanced metadata analysis on a PE file."""
    if not file_path:
        raise FileNotFoundError(f"The file {file_path} does not exist.")
    
    metadata = extract_metadata(file_path)
    pe_header = extract_pe_header(file_path)
    section_headers = extract_section_headers(file_path)
    
    # Combine all the results into one dictionary
    analysis_result = {
        'metadata': metadata,
        'pe_header': pe_header,
        'sections': section_headers,
    }

    return analysis_result

if __name__ == "__main__":
    file_path = input("Enter the file path for analysis: ")
    result = analyze_pe_file(file_path)
    
    print("\n[*] Metadata Extracted:")
    for key, value in result['metadata'].items():
        print(f"{key.capitalize()}: {value}")
    
    print("\n[*] File Header Inspection:")
    for key, value in result['pe_header'].items():
        print(f"{key.capitalize()}: {value}")

    print("\n[*] Section Headers:")
    for section in result['sections']:
        print(f"Section Name: {section['name']}")
        print(f"  Virtual Address: {section['virtual_address']}")
        print(f"  Virtual Size: {section['virtual_size']}")
        print(f"  Raw Size: {section['raw_size']}")
        print(f"  Characteristics: {section['characteristics']}")
        print("-" * 40)
