import lief 
import argparse
import sys
import json
from pathlib import Path

def parse_binary(file_path: str) -> dict:
    """ Parses a binary executable file to extract metadata.

        Core of binary analysis, providing necessary info for the hybrid 
        correlation engine.

        Args:
            file_path: Path to the executable file

        Returns:
            A dict containing the extracted metadata, or empty dict if
            parsing fails or the file doesnt exist.
    """

    binary_path = Path(file_path)
    if not binary_path.is_file():
        print(f"[-] Error: File not found at '{file_path}'", file=sys.stderr)
        return {}
    
    print(f"[*] Parsing '{file_path}'...")
    metadata = {
        "file_path": str(binary_path),
        "format": "Unknown",
        "sections": {},
        "functions": []
    }

    try:
        # LIEF automatically detects format (ELF, PE, Mach-O)
        binary = lief.parse(file_path)

        if not binary:
            print(f"[-] Error: LIEF could not parse the file.", file=sys.stderr)
            return {}
        
        metadata["format"] = binary.format.name

        # Extract .text section info (executable code)
        text_section = binary.get_section(".text")
        if text_section:
            metadata["sections"]["text"] = {
                "virtual_address": hex(text_section.virtual_address),
                "size": text_section.size
            }
        
        # Extract .data section info (initialized data)
        data_section = binary.get_section(".data")
        if data_section:
            metadata["sections"]["data"] = {
                "virtual_address": hex(data_section.virtual_address),
                "size": data_section.size
            }
        
        # Extract function symbols
        if binary.has_symbol:
            for symbol in binary.symbols:
                if symbol.is_function:
                    metadata["functions"].append({
                        "name": symbol.name,
                        "address": hex(symbol.value)
                    })
    
    except Exception as e:
        print(f"[-] An error occured during parsing: {e}", file=sys.stderr)
        return {}
    
    print(f"[*] Successfully extracted metadata for {metadata['format']} file.")
    return metadata

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Parse a binary executable and extract key metadata."
    )
    parser.add_argument(
        "binary_path",
        help="The file path to the binary executable (e.g., /bin/ls)."
    )
    args = parser.parse_args()

    extracted_data = parse_binary(args.binary_path)

    if extracted_data:
        print("\n--- Extracted Metadata ---")
        print(json.dumps(extracted_data, indent=4))
        print("------------------------------")