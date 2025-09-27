import math
import numpy as np
from collections import Counter
from typing import List, Any, Dict
from pprint import pprint

def calculate_shannon_entropy(values: List[Any]) -> float:
    if not values:
        return 0.0
    
    counts = Counter(values)
    total_count = len(values)
    entropy = 0.0

    for count in counts.values():
        probability = count/total_count
        entropy -= probability * math.log2(probability)
    
    return entropy

def calculate_cardinality(values: List[Any]) -> int:
    return len(set(values))

def calculate_correlation(field_values: List[float], message_lengths: List[int]) -> float:
    if len(field_values) < 2 or len(field_values) != len(message_lengths):
        return 0.0
    
    # check if there is variance to avoid numpy errors
    if np.std(field_values) == 0 or np.std(message_lengths) == 0:
        return 0.0
    
    # +1.0 -> strong positive linear relation, 
    # 0 -> no relation
    # -1.0 -> strong negative linear relationship
    correlation_matrix = np.corrcoef(field_values, message_lengths)

    # correlation matrix:
    # [[ corr(field, field),    corr(field, msglen) ],
    #  [ corr(msglen, field),   corr(msglen, msglen)]]
    return correlation_matrix[0, 1] # corr (field, msglen)

def check_session_constancy(field_values: List[Any], session_ids: List[Any]) -> bool:
    """ Checks if a field's tru value is const withing a session but varies b/w sessions.
        Returns True only if both conditions are met.
    """
    if len(field_values) < 2 or len(field_values) != len(session_ids):
        return False
    
    sessions = {}
    for session_id, value in zip(session_ids, field_values):
        sessions.setdefault(session_id, []).append(value)

    # a single session cannot be a session identifier
    if len(sessions) < 2:
        return False
    
    session_values = []
    for values_in_session in sessions.values():
        # condition 1: value must be cosntant withing each session
        if len(set(values_in_session)) != 1:
            return False
        session_values.append(values_in_session[0])
    
    # condition 2: const value must vary between sessions
    if len(set(session_values)) > 1:
        return True
    
    return False

def extract_value_based_features(field_instances: List[Dict[str, Any]]) -> Dict[str, Any]:
    """ Extract all value-vased features for a given field.

        Args:
            field_instances: A list of dicts, where each dict represents an occurance
                             of a field and contains its value and context.
                             Example: [
                                {'value': 100, 'message_length': 120, 'session_id': 'A'},
                                {'value': 100, 'message_length': 122, 'session_id': 'A'},
                                {'value': 250, 'message_length': 270, 'session_id': 'B'}
                             ]
        Returns:
            A dict containing all calculated value-based features.
    """

    if not field_instances:
        return {}
    
    values = [inst['value'] for inst in field_instances]
    message_lengths = [inst['message_length'] for inst in field_instances]
    session_ids = [inst['session_id'] for inst in field_instances]

    # try to convert values to numeric for correlation
    # but dont fail if they are strings.
    numeric_values = []
    try:
        numeric_values = [float(v) for v in values]
    except (ValueError, TypeError):
        numeric_values = [0.0]*len(values) # assign a neutral value if not numeric
    
    features = {
        "cardinality": calculate_cardinality(values),
        "shannon_entropy": calculate_shannon_entropy(values),
        "correlation_with_length": calculate_correlation(numeric_values, message_lengths),
        "is_session_identifier": check_session_constancy(values, session_ids),
    }
    return features

def extract_context_based_features(binary_model: Dict[str, Any]) -> Dict[str, Any]:
    """ Extracts context-based features from binary analysis mode.
        bag-of-words count of instruction mnemonics.
    """
    if not binary_model or "mnemonic_counts" not in binary_model:
        return {}
    return binary_model["mnemonic_counts"]

def extract_features(
        field_instances: List[Dict[str, Any]],
        binary_model: Dict[str, Any]
) -> Dict[str, Any]:
    """ Main orchestrator that calls helper func to build complete feature set.
    """
    value_features = extract_value_based_features(field_instances)
    context_features = extract_context_based_features(binary_model)

    return {
        "value_based": value_features,
        "context-based": context_features
    }


if __name__ == '__main__':
    # example to demonstrate the functions.
    print("---------------------------- Feature Extraction Starting... ----------------------------")
    print("[*] Demonstrating Feature Extractor...")
    mock_field_instances = [
        {'value': '00a1', 'message_length': 120, 'session_id': 'A'},
        {'value': '00a1', 'message_length': 122, 'session_id': 'A'},
        {'value': '00f3', 'message_length': 270, 'session_id': 'B'},
    ]
    mock_binary_model = {
        "mnemonic_counts": {
            "mov": 1023,
            "cmp": 181,
            "lea": 484,
        }
    }
    extracted_features = extract_features(mock_field_instances, mock_binary_model)

    print("[+] Final combined extracted features: ")
    pprint(extracted_features)

    print("---------------------------- Feature Extraction Complete. ----------------------------")

