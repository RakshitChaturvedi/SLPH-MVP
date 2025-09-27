import crc
from typing import Dict, Any, List

# --- Checksum calculation helpers ---

def internet_checksum(data: bytes) -> int:
    """ Standard 16 bit internet checksum algorithm.
    """
    s = 0

    # process 16-bit words
    for i in range(0, len(data), 2):
        w = data[i] + (data[i+1] << 8)
        s += w

    # handle odd length data
    if len(data) % 2 != 0:
        s += data[-1]

    # fold 32-bit sum to 16 bits
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    return ~s & 0xffff

# define a list of checksum funcs to test against.
# each func takes bytes and returns an integer.
CHECKSUM_ALGORITHMS = {
    "CRC-32": lambda data: crc.Crc32(data),
    "CRC-16-XMODEM": lambda data: crc.Crc16.XMODEM(data),
    "Internet Checksum": internet_checksum
}

def is_checksum(field_def: Dict[str, Any], raw_messages: List[str]) -> bool:
    """ Brute-force check to see if field is checksum.
        
        Args:
            field_def: definition of field, including offset and length.
            raw_messages: list of raw mssg payloads (in hex).
        
        Returns:
            True if field value consistently matches calculated checksum.
    """

    if not raw_messages:
        return False
    
    field_offset = field_def.get("offset", 0)
    field_len = field_def.get("length", 0)

    for algo_name, algo_func in CHECKSUM_ALGORITHMS.items():
        is_match_for_all = True
        for hex_msg in raw_messages:
            try:
                msg_bytes = bytearray.fromhex(hex_msg)

                # extract original value from field
                field_bytes = msg_bytes[field_offset: field_offset + field_len]
                original_value = int.from_bytes(field_bytes, 'big')

                # create copy of mssg and zero-out the field
                temp_msg_bytes = bytearray(msg_bytes)
                for i in range(field_len):
                    temp_msg_bytes[field_offset + i]  = 0
                
                # calculate te checksum on modified mssg
                calculated_value = algo_func(temp_msg_bytes)

                if calculated_value != original_value:
                    is_match_for_all = False
                    break # algo failed, try next algo
            except (ValueError, IndexError):
                is_match_for_all = False
                break
        
        if is_match_for_all:
            return True # algo worked for all mssgs
    
    return False # no algo matched for all mssgs

# --- Heuristc Classifier ---

def classify_field_heuristically(
        features: Dict[str, Any],
        field_def: Dict[str, Any],
        raw_messages: List[str]
) -> str:
    """ Applies set of high-confidence rules to classify a protocol field.

        Returns:
            A string classification (e.g., "LENGTH", "SESSION_ID", "UNKNOWN").
    """

    value_features = features.get("value_based", {})

    # Rule 1. Lenght field?
    if value_features.get("correlation_with_length", 0) > 0.95:
        return "LENGTH"
    
    # Rule 2. Session ID?
    if value_features.get("is_session_identifier", False):
        return "SESSION_ID"
    
    # Rule 3. Command ID? (check low cardinality and early position in mssg)
    if value_features.get("cardinality", 100) < 16 and field_def.get("offset", 100) < 4:
        return "COMMAND_ID"
    
    # Rule 4. Checksum?
    if is_checksum(field_def, raw_messages):
        return "CHECKSUM"
    
    # if no rules match
    return "UNKNOWN"

if __name__ == '__main__':
    # --- demo ---
    print("[+] Heuristic Classifier Demo")

    # 1. Length field example
    length_features = {
        "value_based": {
            "correlation_with_length": 0.99,
            "is_session_identifier": False,
            "cardinality": 50
        }
    }
    length_def = {"offset":0, "length": 2}
    classification = classify_field_heuristically(length_features, length_def, [])
    print(f"[+] Field with high correlation -> Classified as: {classification}")

    # 2. Session ID Example
    session_features = {
        "value_based": {
            "correlation_with_length": 0.1, 
            "is_session_identifier": True, 
            "cardinality": 3
        }
    }
    session_def = {"offset": 4, "length": 4}
    classification = classify_field_heuristically(session_features, session_def, [])
    print(f"[+] Field with session constancy -> Classified as: {classification}")

    # 3. Command ID Example
    command_features = {
        "value_based": {
            "correlation_with_length": 0.0, 
            "is_session_identifier": False, 
            "cardinality": 4
        }
    }
    command_def = {"offset": 0, "length": 1} # Appears at the start of the message
    classification = classify_field_heuristically(command_features, command_def, [])
    print(f"[+] Field with low cardinality at offset 0 -> Classified as: {classification}")

    # 4. Unknown Example
    unknown_features = {
        "value_based": {
            "correlation_with_length": 0.2, 
            "is_session_identifier": False, 
            "cardinality": 100
        }
    }
    unknown_def = {"offset": 20, "length": 8}
    classification = classify_field_heuristically(unknown_features, unknown_def, [])
    print(f"[+] Generic field -> Classified as: {classification}")