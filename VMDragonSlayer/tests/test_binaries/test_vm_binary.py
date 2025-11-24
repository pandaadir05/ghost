"""
VM Test Binary
==============

Simulate VM-protected binary for testing VM-aware fuzzing.
This mimic behavior of VM-protected malware.
"""

import sys
import struct
import random

# Simulate VM handler addresses
VM_HANDLERS = {
    0x1000: "arithmetic_handler",
    0x1004: "memory_handler",
    0x1008: "control_flow_handler",
    0x100C: "encryption_handler",
    0x1010: "decryption_handler",
}

def simulate_vm_dispatcher(input_data):
    """Simulate VM dispatcher that routes to handlers."""
    if len(input_data) < 4:
        return "input_too_short"

    # Extract "opcode" from input
    opcode = struct.unpack('<I', input_data[:4])[0]

    # Route to handler based on opcode
    handler_addr = opcode & 0xFFFF  # Simulate address calculation

    if handler_addr in VM_HANDLERS:
        handler_name = VM_HANDLERS[handler_addr]
        print(f"[VM] Dispatching to {handler_name} (0x{handler_addr:04x})")

        # Simulate handler execution
        return simulate_vm_handler(handler_name, input_data[4:])
    else:
        print(f"[VM] Unknown opcode: 0x{opcode:08x}")
        return "unknown_opcode"

def simulate_vm_handler(handler_name, data):
    """Simulate execution of VM handler."""
    if handler_name == "arithmetic_handler":
        return simulate_arithmetic_handler(data)
    elif handler_name == "memory_handler":
        return simulate_memory_handler(data)
    elif handler_name == "control_flow_handler":
        return simulate_control_flow_handler(data)
    elif handler_name == "encryption_handler":
        return simulate_encryption_handler(data)
    elif handler_name == "decryption_handler":
        return simulate_decryption_handler(data)
    else:
        return "unknown_handler"

def simulate_arithmetic_handler(data):
    """Simulate arithmetic operations."""
    if len(data) < 8:
        return "insufficient_data"

    try:
        a = struct.unpack('<I', data[:4])[0]
        b = struct.unpack('<I', data[4:8])[0]

        print(f"[VM] Arithmetic: {a} + {b} = {a + b}")

        # Potential division by zero
        if b == 0:
            result = 1000 // b  # This will crash
        else:
            result = a // b

        return f"arithmetic_result_{result}"

    except ZeroDivisionError:
        print("[VM] Division by zero in arithmetic handler!")
        raise  # Re-raise to cause crash
    except Exception as e:
        return f"arithmetic_error_{e}"

def simulate_memory_handler(data):
    """Simulate memory operations."""
    if len(data) < 8:
        return "insufficient_data"

    try:
        base_addr = struct.unpack('<I', data[:4])[0]
        offset = struct.unpack('<I', data[4:8])[0]

        # Simulate memory access
        access_addr = base_addr + offset
        print(f"[VM] Memory access: 0x{access_addr:08x}")

        # Simulate null pointer dereference
        if access_addr == 0:
            print("[VM] Null pointer dereference!")
            # In real binary this would crash
            raise MemoryError("Null pointer")

        # Simulate out of bounds
        if access_addr > 0xFFFFFFF:
            print("[VM] Access violation!")
            raise MemoryError("Access violation")

        return f"memory_access_0x{access_addr:08x}"

    except MemoryError:
        raise  # Re-raise memory errors
    except Exception as e:
        return f"memory_error_{e}"

def simulate_control_flow_handler(data):
    """Simulate control flow operations."""
    if len(data) < 4:
        return "insufficient_data"

    try:
        target = struct.unpack('<I', data[:4])[0]

        print(f"[VM] Control flow to: 0x{target:08x}")

        # Simulate jump to invalid address
        if target == 0:
            print("[VM] Jump to null!")
            raise SystemExit("Invalid jump")

        # Simulate infinite loop detection
        if target == 0xDEADBEEF:
            print("[VM] Infinite loop detected!")
            return "infinite_loop"

        return f"control_flow_0x{target:08x}"

    except SystemExit:
        raise
    except Exception as e:
        return f"control_flow_error_{e}"

def simulate_encryption_handler(data):
    """Simulate encryption operations."""
    if not data:
        return "no_data"

    try:
        # Simple XOR encryption simulation
        key = 0xAA
        encrypted = bytes(b ^ key for b in data)

        print(f"[VM] Encrypted {len(data)} bytes")
        return f"encrypted_{len(encrypted)}_bytes"

    except Exception as e:
        return f"encryption_error_{e}"

def simulate_decryption_handler(data):
    """Simulate decryption operations."""
    if not data:
        return "no_data"

    try:
        # Simple XOR decryption simulation
        key = 0xAA
        decrypted = bytes(b ^ key for b in data)

        print(f"[VM] Decrypted {len(data)} bytes")

        # Check for specific patterns that might cause issues
        if b"CRASH" in decrypted:
            print("[VM] Crash pattern detected in decrypted data!")
            raise ValueError("Crash pattern")

        return f"decrypted_{len(decrypted)}_bytes"

    except ValueError:
        raise
    except Exception as e:
        return f"decryption_error_{e}"

def main():
    """Main VM test program."""
    print("VMDragonSlayer VM Test Binary")
    print("Simulating VM-protected malware behavior")
    print()

    try:
        # Read input
        input_data = sys.stdin.buffer.read(1024)
        print(f"Received {len(input_data)} bytes of input")

        if not input_data:
            print("No input received")
            return 0

        # Simulate VM execution
        result = simulate_vm_dispatcher(input_data)
        print(f"VM execution result: {result}")

        return 0

    except ZeroDivisionError:
        print("Division by zero crash!")
        return 1
    except MemoryError as e:
        print(f"Memory error: {e}")
        return 1
    except SystemExit as e:
        print(f"Control flow error: {e}")
        return 1
    except ValueError as e:
        print(f"Value error: {e}")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
