import numpy as np 

def get_mock_message_groups():
    """
    Generates two distinct and predictable groups of messages for testing.
    - Group A is based on a repeating 'aabb' pattern.
    - Group B is based on a repeating 'ccdd' pattern.
    """
    mock_group_a_messages = []
    for i in range(8):

        variable_part = f"{i:02x}" # Produces '00', '01', '02', etc.
        payload_hex = ('aabb' * 20) + variable_part
        mock_group_a_messages.append({
            'payload_hex': payload_hex,
            'payload_string': f'GROUP_A_PKT_{i}'
        })

    mock_group_b_messages = []
    for i in range(8):
        variable_part = f"{i+10:02x}" # Produces '0a', '0b', etc.
        payload_hex = ('ccdd' * 20) + variable_part
        mock_group_b_messages.append({
            'payload_hex': payload_hex,
            'payload_string': f'GROUP_B_PKT_{i}'
        })
    
    return mock_group_a_messages, mock_group_b_messages