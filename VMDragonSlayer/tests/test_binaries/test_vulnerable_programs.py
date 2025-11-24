"""
Test Binaries for Fuzzer Validation
====================================

Simple test program to validate fuzzer functionality.
These have known vulnerability for testing crash detection.
"""

import os
import sys
import struct

def test_buffer_overflow():
    """Test binary with buffer overflow vulnerability."""
    print("Buffer Overflow Test Program")
    print("Reading input from stdin...")

    # Read input (vulnerable to overflow)
    try:
        data = sys.stdin.buffer.read(1024)
        print(f"Received {len(data)} bytes")

        # Copy to small buffer (overflow!)
        buffer = bytearray(64)
        buffer[:len(data)] = data[:64]  # Truncate but still vulnerable

        # Try to access beyond buffer
        if len(data) > 64:
            # This will cause access violation if data is crafted
            index = data[0] + data[1] * 256
            if index < len(buffer):
                print(f"Accessing buffer[{index}] = {buffer[index]}")
            else:
                print("Index out of bounds!")

    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0

def test_division_by_zero():
    """Test binary with division by zero."""
    print("Division by Zero Test Program")

    try:
        data = sys.stdin.buffer.read(4)
        if len(data) < 4:
            return 0

        # Extract integer from input
        value = struct.unpack('<I', data[:4])[0]
        print(f"Value: {value}")

        # Divide by input value (zero = crash)
        result = 1000 // value
        print(f"1000 / {value} = {result}")

    except ZeroDivisionError:
        print("Division by zero detected!")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0

def test_null_pointer():
    """Test binary with null pointer dereference."""
    print("Null Pointer Test Program")

    try:
        data = sys.stdin.buffer.read(8)
        if len(data) < 8:
            return 0

        # Extract pointer from input
        ptr_value = struct.unpack('<Q', data[:8])[0]
        print(f"Pointer value: 0x{ptr_value:016x}")

        # Try to dereference (if null = crash)
        if ptr_value == 0:
            print("Attempting null pointer dereference...")
            # This would crash in real binary
            print("Null pointer accessed!")
            return 1
        else:
            print("Valid pointer")

    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0

def test_format_string():
    """Test binary with format string vulnerability."""
    print("Format String Test Program")

    try:
        data = sys.stdin.buffer.read(256)
        if not data:
            return 0

        # Try to decode as string
        try:
            format_str = data.decode('utf-8', errors='ignore').rstrip('\x00')
            print(f"Format string: {repr(format_str)}")

            # Use as format string (vulnerable!)
            result = format_str % (1, 2, 3, 4, 5)  # This could crash with %n etc
            print(f"Formatted result: {result}")

        except Exception as e:
            print(f"Format error: {e}")
            return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0

def test_heap_corruption():
    """Test binary with heap corruption."""
    print("Heap Corruption Test Program")

    try:
        data = sys.stdin.buffer.read(128)
        if len(data) < 8:
            return 0

        # Extract size from input
        size = struct.unpack('<I', data[:4])[0]
        print(f"Requested size: {size}")

        # Allocate buffer (could be very large)
        if size > 1024 * 1024:  # 1MB limit
            print("Size too large")
            return 1

        buffer = bytearray(size)

        # Fill with pattern
        for i in range(min(size, len(data) - 4)):
            buffer[i] = data[i + 4]

        print(f"Allocated and filled {size} bytes")

        # Try to access (could be out of bounds)
        access_offset = struct.unpack('<I', data[4:8])[0] if len(data) >= 8 else 0
        if access_offset < size:
            print(f"Accessing buffer[{access_offset}] = {buffer[access_offset]}")
        else:
            print("Access out of bounds!")

    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0

def main():
    """Main test program dispatcher."""
    if len(sys.argv) != 2:
        print("Usage: python test_binary.py <test_type>")
        print("Test types: buffer_overflow, division_by_zero, null_pointer, format_string, heap_corruption")
        return 1

    test_type = sys.argv[1]

    if test_type == "buffer_overflow":
        return test_buffer_overflow()
    elif test_type == "division_by_zero":
        return test_division_by_zero()
    elif test_type == "null_pointer":
        return test_null_pointer()
    elif test_type == "format_string":
        return test_format_string()
    elif test_type == "heap_corruption":
        return test_heap_corruption()
    else:
        print(f"Unknown test type: {test_type}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
