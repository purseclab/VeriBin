def parse_spec_string(spec_str, initial_argument_number):
    """
    Parse a spec string and return the total number of arguments and the indices of the pointers in the argument list.
    The returned values should add the initial_argument_number to number of arguments and to the indices of the pointers.
    """
    # Preprocess the spec str
    if spec_str.startswith("String{"):
        spec_str = spec_str.replace("String{", "").replace("}", "")
        print(f"Preprocessed spec string: {spec_str}")

    # Map of spec characters to number of arguments they correspond to and pointer indices
    spec_map = {
        's': (2, [0, 1]),      # String: two arguments, a pointer to the string and a pointer to its length
        'l': (1, [0]),      # Long: one argument, a pointer to the long integer
        'd': (1, [0]),      # Double: one argument, a pointer to double
        'b': (1, [0]),      # Boolean: one argument, a pointer to boolean
        'r': (1, [0]),      # Resource: one argument, a pointer to the resource
        'a': (1, [0]),      # Array: one argument, a pointer to the array
        'o': (1, [0]),      # Object: one argument, a pointer
        'O': (2, [0]),      # Object with class entry: two arguments, the first is a pointer
        'z': (1, [0]),      # zval: one argument, a pointer to zval
        'h': (1, [0]),      # HashTable: one argument, a pointer
        'f': (2, [0, 1]),      # Function: two arguments, a pointer to a zval representing the function and a pointer to a zend_fcall_info_cache structure
        'p': (2, [0, 1]),      # Path: two arguments, similar to 's' but checks for null bytes and length.
        '|': (0, []),       # Optional indicator: no arguments
        '!': (0, []),       # Nullable indicator: no arguments
        '/': (0, [])        # Separate indicator: no arguments
    }

    total_args = 0
    pointer_indices = []

    for i, char in enumerate(spec_str):

        if char in spec_map:
            num_args, pointer_pos = spec_map[char]
            if num_args > 0:
                for pos in pointer_pos:
                    # print(f"Adding pointer index: {total_args + pos}")
                    pointer_indices.append(total_args + pos)
                total_args += num_args
        else:
            raise ValueError(f"Unknown specifier '{char}' in spec string.")

    # Add the initial_argument_number to number of arguments and the pointer indices
    total_args += initial_argument_number
    pointer_indices = [initial_argument_number + i for i in pointer_indices]

    return total_args, pointer_indices

if __name__ == "__main__":
    # Example usage
    # 6, [0, 2, 4, 5]
    # After adding the base index of 2, expecting 9 and [2, 3, 5, 7, 8]
    # spec_str = "OOl|l"

    # 4, [0, 1, 2, 3]
    # After adding the base index of 2, expecting 7 and [2, 3, 4, 5, 6]
    spec_str = "sz|b"
    total_args, pointer_indices = parse_spec_string(spec_str, initial_argument_number=3)
    print(f"Total arguments: {total_args}")
    print(f"Pointer indices: {pointer_indices}")
