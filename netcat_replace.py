import sys
import socket
import getopt
import threading
import subprocess

listen = False
command = False
upload = False
execute = ''
target = ""
upload_destination = ""
port = 0

def usage():
    print("\n" + "="*50)
    print("PRASUN's Net Tool")
    print("="*50)
    print("\nUsage: netcat_replace.py -t target_host -p port [options]")
    print("\nOptions:")
    print("  -l, --listen              Listen on [host]:[port] for incoming connections")
    print("  -e, --execute=command     Execute command upon receiving a connection")
    print("  -c, --command             Initialize a command shell")
    print("  -u, --upload=destination  Upload a file and write to [destination]")
    print("  -t, --target=host         Target host IP address")
    print("  -p, --port=port           Port number")
    print("\nExamples:")
    print("\n  LISTENER (Server - machine to be controlled):")
    print("    python netcat_replace.py -l -p 5555 -c")
    print("    python netcat_replace.py -l -p 5555 -e='cat /etc/passwd'")
    print("    python netcat_replace.py -l -p 5555 -u=/tmp/uploaded.txt")
    print("\n  SENDER (Client - controlling machine):")
    print("    python netcat_replace.py -t 192.168.1.100 -p 5555")
    print("    echo 'ls -la' | python netcat_replace.py -t 192.168.1.100 -p 5555")
    print("\n  Quick test on same machine:")
    print("    Terminal 1: python netcat_replace.py -l -p 5555 -c")
    print("    Terminal 2: python netcat_replace.py -t 127.0.0.1 -p 5555")
    print("="*50 + "\n")
    sys.exit(0)

def client_sender(buffer):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        print(f"[*] Connecting to {target}:{port}...")
        client.connect((target, port))
        print(f"[+] Connected to {target}:{port}\n")

        # Send initial buffer if provided
        if len(buffer):
            # Handle both string and bytes
            if isinstance(buffer, str):
                buffer = buffer.encode()
            client.send(buffer)
            print(f"[*] Sent {len(buffer)} bytes")
        
        # Set a timeout for receiving data
        client.settimeout(1.0)
        
        while True:
            response = b""
            
            # Keep receiving until we get the prompt or timeout
            try:
                while True:
                    data = client.recv(1024)
                    if not data:
                        print("[*] Connection closed by server.")
                        return
                    
                    response += data
                    
                    # Check if we received the prompt
                    if b"<PNC:#>" in response:
                        break
                        
            except socket.timeout:
                # If timeout and we have some data, that's ok
                if not response:
                    continue
            
            # Display what we received
            if response:
                decoded = response.decode('utf-8', errors='ignore')
                print(decoded, end='', flush=True)
            
            # Get user input
            try:
                buffer = input()
                buffer += "\n"
                client.send(buffer.encode())
            except (EOFError, KeyboardInterrupt):
                print("\n[*] User terminated.")
                break
                
    except ConnectionRefusedError:
        print(f"[!] Connection refused. Is the listener running on {target}:{port}?")
    except Exception as e:
        print(f"[!] Exception: {e}")
    finally:
        client.close()
        print("[*] Connection closed.")


def server_loop():
    global target, port
    
    # if no target is defined, we listen on all interfaces
    if not len(target):
        target = "0.0.0.0"
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((target, port))
        server.listen(5)
        print(f"[*] Listening on {target}:{port}")
        print("[*] Waiting for connections...")
    except OSError as e:
        if "Address already in use" in str(e) or "Only one usage" in str(e):
            print(f"[!] Port {port} is already in use.")
            print(f"[*] Trying to find an available port...")
            
            # Try to find an available port
            for try_port in range(port + 1, port + 100):
                try:
                    server.bind((target, try_port))
                    port = try_port
                    server.listen(5)
                    print(f"[+] Found available port: {port}")
                    print(f"[*] Listening on {target}:{port}")
                    print(f"[!] IMPORTANT: Connect using: python netcat_replace.py -t {target if target != '0.0.0.0' else '127.0.0.1'} -p {port}")
                    print("[*] Waiting for connections...")
                    break
                except:
                    continue
            else:
                print(f"[!] Could not find available port in range {port}-{port+100}")
                sys.exit(1)
        else:
            print(f"[!] Failed to bind to {target}:{port}")
            print(f"[!] Error: {e}")
            sys.exit(1)
    
    while True:
        client_socket, addr = server.accept()
        print(f"[+] Accepted connection from {addr[0]}:{addr[1]}")
        
        # spin off a thread to handle our new client
        client_thread = threading.Thread(target=client_handler, args=(client_socket,))
        client_thread.start()

        
def run_command(command):
    # trim the newline
    command = command.rstrip()
    
    if not command:
        return b""
    
    # run the command and get the output back
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
    except Exception as e:
        output = f"Failed to execute command: {str(e)}\r\n".encode()
    
    return output    

    
def client_handler(client_socket):
    global upload
    global execute
    global command
    
    # check for upload
    if len(upload_destination):
        print("[*] Receiving file...")
        file_buffer = b""
    
        # keep reading data until none is available
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            else:
                file_buffer += data
        
        # now we take these bytes and try to write them out
        try:
            file_descriptor = open(upload_destination, "wb")
            file_descriptor.write(file_buffer)
            file_descriptor.close()
            
            msg = f"[+] Successfully saved file to {upload_destination}\r\n"
            client_socket.send(msg.encode())
            print(msg.strip())
        except Exception as e:
            msg = f"[!] Failed to save file to {upload_destination}: {str(e)}\r\n"
            client_socket.send(msg.encode())
            print(msg.strip())
    
    # check for command execution
    if len(execute):
        print(f"[*] Executing: {execute}")
        output = run_command(execute)
        client_socket.send(output)

    # now we go into another loop if a command shell was requested
    if command:
        print("[*] Starting command shell...")
        
        try:
            while True:
                # show a simple prompt
                prompt = b"<PNC:#> "
                client_socket.send(prompt)
                print(f"[DEBUG] Sent prompt to client")
                
                # now we receive until we see a linefeed (enter key)
                cmd_buffer = b""
                while b"\n" not in cmd_buffer:
                    chunk = client_socket.recv(1024)
                    if not chunk:
                        print("[*] Client disconnected.")
                        return
                    cmd_buffer += chunk
                
                command_str = cmd_buffer.decode('utf-8', errors='ignore').strip()
                print(f"[DEBUG] Received command: {command_str}")
                
                # send back the command output
                response = run_command(cmd_buffer.decode('utf-8', errors='ignore'))
                
                # send back the response
                if response:
                    client_socket.send(response)
                    print(f"[DEBUG] Sent response ({len(response)} bytes)")
                    
        except Exception as e:
            print(f"[!] Error in command shell: {e}")
        finally:
            client_socket.close()


def main():
    global listen
    global port
    global execute
    global command
    global upload_destination
    global target
    
    if not len(sys.argv[1:]):
        usage()
    
    # read the commandline options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hle:t:p:cu:", 
                                   ["help", "listen", "execute", "target", "port", "command", "upload"])
    except getopt.GetoptError as err:
        print(f"[!] Error: {str(err)}")
        usage()
    
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-l", "--listen"):
            listen = True
        elif o in ("-e", "--execute"):
            execute = a
        elif o in ("-c", "--command"):
            command = True
        elif o in ("-u", "--upload"):
            upload_destination = a
        elif o in ("-t", "--target"):
            target = a
        elif o in ("-p", "--port"):
            port = int(a)
        else:
            assert False, "Unhandled Option"
    
    # Validate required options
    if not listen and (not target or port == 0):
        print("[!] Error: Client mode requires -t (target) and -p (port)")
        usage()
    
    if listen and port == 0:
        print("[!] Error: Listener mode requires -p (port)")
        usage()
    
    # are we going to listen or just send data from stdin?
    if not listen and len(target) and port > 0:
        # Check if reading from stdin (pipe) or if we should read a file
        import select
        
        # Check if stdin has data (is a pipe)
        if select.select([sys.stdin,], [], [], 0.0)[0]:
            # Read binary data from stdin
            buffer = sys.stdin.buffer.read()
        else:
            # No piped input, read as text
            buffer = sys.stdin.read().encode()
        
        # send data off
        client_sender(buffer)
    
    # we are going to listen and potentially
    # upload things, execute commands, and drop a shell back
    if listen:
        server_loop()

        
if __name__ == '__main__':
    main()