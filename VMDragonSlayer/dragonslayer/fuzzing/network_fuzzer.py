"""
Network Fuzzing Support
========================

Support fuzzing network protocol and service.
This extend fuzzer to work with socket-based target.
"""

from typing import Optional, Tuple, List, Dict
import socket
import time
import threading
import select
from .execution_engine import ExecutionResult


class NetworkTarget:
    """
    Represent network target for fuzzing.
    
    Support TCP/UDP connection with timeout and retry.
    """
    
    def __init__(self, host: str, port: int, protocol: str = 'tcp',
                 timeout: float = 5.0, retries: int = 3):
        """
        Initialize network target.
        
        Args:
            host: Target hostname/IP
            port: Target port
            protocol: 'tcp' or 'udp'
            timeout: Connection timeout in second
            retries: Number of connection retry
        """
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.timeout = timeout
        self.retries = retries
        
        if self.protocol not in ['tcp', 'udp']:
            raise ValueError(f"Unsupported protocol: {protocol}")
            
    def connect(self) -> Optional[socket.socket]:
        """Establish connection to target."""
        for attempt in range(self.retries):
            try:
                if self.protocol == 'tcp':
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    
                sock.settimeout(self.timeout)
                sock.connect((self.host, self.port))
                
                return sock
                
            except (socket.timeout, socket.error) as e:
                if attempt == self.retries - 1:
                    return None
                time.sleep(0.1 * (attempt + 1))  # Exponential backoff
                
        return None
        
    def send_receive(self, data: bytes, receive_timeout: float = 2.0) -> Tuple[bytes, bool]:
        """
        Send data and receive response.
        
        Return (response_data, connection_alive)
        """
        sock = self.connect()
        if not sock:
            return b"", False
            
        try:
            # Send data
            sock.send(data)
            
            # Receive response
            response = b""
            sock.settimeout(receive_timeout)
            
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    
                    # Check for reasonable response size
                    if len(response) > 1024 * 1024:  # 1MB limit
                        break
                        
                except socket.timeout:
                    break
                    
            return response, True
            
        except Exception as e:
            return b"", False
        finally:
            try:
                sock.close()
            except:
                pass


class NetworkFuzzer:
    """
    Fuzzer for network protocol.
    
    Send fuzz input over network and monitor response.
    Detect crash by connection failure or abnormal response.
    """
    
    def __init__(self, target: NetworkTarget):
        self.target = target
        self.baseline_responses: List[bytes] = []
        self.crash_signatures: List[bytes] = []
        
    def establish_baseline(self, normal_inputs: List[bytes]):
        """
        Establish baseline of normal response.
        
        This help detect abnormal behavior.
        """
        print("[*] Establishing baseline responses...")
        
        for input_data in normal_inputs:
            response, alive = self.target.send_receive(input_data)
            
            if alive and response:
                self.baseline_responses.append(response)
                
        print(f"[+] Collected {len(self.baseline_responses)} baseline response")
        
    def execute_network_input(self, input_data: bytes) -> ExecutionResult:
        """
        Execute input over network.
        
        Return execution result with crash detection.
        """
        result = ExecutionResult()
        start_time = time.time()
        
        try:
            response, connection_alive = self.target.send_receive(input_data)
            
            result.execution_time = time.time() - start_time
            result.stdout = response
            
            # Check for crash indicators
            if not connection_alive:
                result.crashed = True
                result.crash_info = {
                    'type': 'connection_failed',
                    'reason': 'Target not responding'
                }
            elif self._is_abnormal_response(response):
                result.crashed = True
                result.crash_info = {
                    'type': 'abnormal_response',
                    'response_length': len(response)
                }
            elif response in self.crash_signatures:
                result.crashed = True
                result.crash_info = {
                    'type': 'known_crash_signature',
                    'signature': response[:50].hex()
                }
                
        except Exception as e:
            result.crashed = True
            result.crash_info = {'error': str(e)}
            result.execution_time = time.time() - start_time
            
        return result
        
    def _is_abnormal_response(self, response: bytes) -> bool:
        """
        Check if response is abnormal compare to baseline.
        
        Look for unusual length, content, or pattern.
        """
        if not self.baseline_responses:
            return False
            
        # Check length difference
        baseline_lengths = [len(r) for r in self.baseline_responses]
        avg_length = sum(baseline_lengths) / len(baseline_lengths)
        
        if abs(len(response) - avg_length) > avg_length * 2:
            return True
            
        # Check for crash indicator in response
        crash_indicators = [
            b"Segmentation fault",
            b"Access violation",
            b"Exception",
            b"ERROR",
            b"CRASH",
            b"\x00\x00\x00\x00" * 10,  # Lots of NULLs
        ]
        
        for indicator in crash_indicators:
            if indicator in response:
                return True
                
        return False
        
    def add_crash_signature(self, signature: bytes):
        """Add known crash signature."""
        if signature not in self.crash_signatures:
            self.crash_signatures.append(signature)


class ProtocolFuzzer(NetworkFuzzer):
    """
    Specialized fuzzer for specific protocol.
    
    Add protocol-aware mutation and parsing.
    """
    
    def __init__(self, target: NetworkTarget, protocol_name: str):
        super().__init__(target)
        self.protocol_name = protocol_name
        self.protocol_parser = self._get_protocol_parser()
        
    def _get_protocol_parser(self):
        """Get protocol-specific parser."""
        parsers = {
            'http': self._parse_http,
            'ftp': self._parse_ftp,
            'smtp': self._parse_smtp,
        }
        
        return parsers.get(self.protocol_name.lower(), self._parse_generic)
        
    def generate_protocol_input(self, template: bytes, mutate: bool = True) -> bytes:
        """
        Generate protocol-aware input.
        
        Use template and apply protocol-specific mutation.
        """
        if not mutate:
            return template
            
        # Parse template
        parsed = self.protocol_parser(template)
        
        # Apply mutation base on protocol
        if self.protocol_name.lower() == 'http':
            return self._mutate_http(parsed)
        elif self.protocol_name.lower() == 'ftp':
            return self._mutate_ftp(parsed)
        else:
            return self._mutate_generic(template)
            
    def _parse_http(self, data: bytes) -> Dict:
        """Parse HTTP request."""
        try:
            lines = data.split(b'\r\n')
            if not lines:
                return {}
                
            # Parse request line
            request_line = lines[0].decode('utf-8', errors='ignore')
            parts = request_line.split()
            
            return {
                'method': parts[0] if len(parts) > 0 else 'GET',
                'path': parts[1] if len(parts) > 1 else '/',
                'version': parts[2] if len(parts) > 2 else 'HTTP/1.1',
                'headers': lines[1:],
                'body': b''
            }
        except:
            return {}
            
    def _mutate_http(self, parsed: Dict) -> bytes:
        """Apply HTTP-specific mutation."""
        import random
        
        # Mutate method
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
        method = random.choice(methods)
        
        # Mutate path
        paths = ['/', '/admin', '/api', '/login', '/../../etc/passwd']
        path = random.choice(paths)
        
        # Add random headers
        headers = [
            f"Host: {random.choice(['localhost', 'example.com', '127.0.0.1'])}",
            f"User-Agent: {random.choice(['Mozilla/5.0', 'curl/7.68.0', 'Python/3.8'])}",
            f"Content-Length: {random.randint(0, 1000)}",
        ]
        
        # Build request
        request = f"{method} {path} HTTP/1.1\r\n"
        for header in headers:
            request += f"{header}\r\n"
        request += "\r\n"
        
        return request.encode()
        
    def _parse_ftp(self, data: bytes) -> Dict:
        """Parse FTP command."""
        return {}
        
    def _mutate_ftp(self, parsed: Dict) -> bytes:
        """Apply FTP-specific mutation."""
        import random
        commands = ['USER', 'PASS', 'RETR', 'STOR', 'LIST', 'CWD']
        command = random.choice(commands)
        arg = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=10))
        return f"{command} {arg}\r\n".encode()
        
    def _parse_smtp(self, data: bytes) -> Dict:
        """Parse SMTP command."""
        return {}
        
    def _parse_generic(self, data: bytes) -> Dict:
        """Generic parser."""
        return {'data': data}
        
    def _mutate_generic(self, data: bytes) -> bytes:
        """Generic mutation."""
        import random
        result = bytearray(data)
        
        # Random byte mutation
        for _ in range(random.randint(1, len(result) // 10 + 1)):
            pos = random.randint(0, len(result) - 1)
            result[pos] = random.randint(0, 255)
            
        return bytes(result)


class DistributedFuzzer:
    """
    Distribute fuzzing across multiple machine.
    
    Use network coordination to share corpus and result.
    """
    
    def __init__(self, coordinator_host: str = 'localhost', coordinator_port: int = 9999):
        self.coordinator_host = coordinator_host
        self.coordinator_port = coordinator_port
        self.is_coordinator = False
        self.workers: List[Tuple[str, int]] = []
        
    def start_coordinator(self):
        """Start as coordinator node."""
        self.is_coordinator = True
        
        # Start coordination server
        server_thread = threading.Thread(target=self._coordinator_server)
        server_thread.daemon = True
        server_thread.start()
        
    def connect_to_coordinator(self):
        """Connect to coordinator as worker."""
        # Worker logic would go here
        pass
        
    def _coordinator_server(self):
        """Run coordinator server."""
        # Simple TCP server for coordination
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_sock.bind((self.coordinator_host, self.coordinator_port))
            server_sock.listen(10)
            
            print(f"[+] Coordinator listening on {self.coordinator_host}:{self.coordinator_port}")
            
            while True:
                client_sock, addr = server_sock.accept()
                print(f"[+] Worker connected from {addr}")
                
                # Handle worker in separate thread
                worker_thread = threading.Thread(
                    target=self._handle_worker,
                    args=(client_sock, addr)
                )
                worker_thread.daemon = True
                worker_thread.start()
                
        except Exception as e:
            print(f"[!] Coordinator error: {e}")
        finally:
            server_sock.close()
            
    def _handle_worker(self, sock: socket.socket, addr: Tuple[str, int]):
        """Handle communication with worker."""
        try:
            # Simple protocol: receive status, send corpus updates
            while True:
                data = sock.recv(1024)
                if not data:
                    break
                    
                # Process worker message
                message = data.decode('utf-8', errors='ignore').strip()
                
                if message.startswith('STATUS:'):
                    # Worker status update
                    print(f"[+] Worker {addr}: {message}")
                    
                elif message.startswith('CRASH:'):
                    # New crash found
                    print(f"[+] New crash from worker {addr}")
                    
        except Exception as e:
            print(f"[!] Error handling worker {addr}: {e}")
        finally:
            sock.close()
