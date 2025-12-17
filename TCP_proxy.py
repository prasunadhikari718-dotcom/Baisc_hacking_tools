import sys
import socket
import threading

def hexdump(src, length=16):
    """Pretty hex dumping function"""
    if isinstance(src, bytes):
        src = src.decode('latin-1')
    
    result = []
    for i in range(0, len(src), length):
        s = src[i:i+length]
        hexa = ' '.join(["%02X" % ord(x) for x in s])
        text = ''.join([x if 0x20 <= ord(x) < 0x7F else '.' for x in s])
        result.append("%04X   %-*s   %s" % (i, length*3, hexa, text))
    
    print('\n'.join(result))


def receive_from(connection):
    """Receive data from a connection"""
    buffer = b""
    
    # Set a shorter timeout for faster responses
    connection.settimeout(0.1)
    
    try:
        # Keep reading into the buffer until there's no more data or we time out
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except socket.timeout:
        # Timeout is normal - means no more data available right now
        pass
    except Exception as e:
        if buffer:
            # We got some data before the error, return it
            pass
        else:
            print(f"[!] Error receiving data: {e}")
    
    return buffer


def request_handler(buffer):
    """Modify any requests destined for the remote host"""
    # Perform packet modifications here
    # For now, just pass through unchanged
    return buffer


def response_handler(buffer):
    """Modify any responses destined for the local host"""
    # Perform packet modifications here
    # For now, just pass through unchanged
    return buffer


def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    """Handle the proxy connection between client and remote host"""
    
    print(f"[*] Starting proxy handler for connection")
    
    # Connect to the remote host
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        print(f"[*] Attempting to connect to {remote_host}:{remote_port}")
        remote_socket.connect((remote_host, remote_port))
        print(f"[+] Connected to remote host {remote_host}:{remote_port}")
        
        # Receive data from the remote end if necessary
        if receive_first:
            print("[*] Receiving initial data from remote...")
            remote_buffer = receive_from(remote_socket)
            if remote_buffer:
                print(f"[<==] Received {len(remote_buffer)} bytes from remote.")
                hexdump(remote_buffer)
                
                # Send it to our response handler
                remote_buffer = response_handler(remote_buffer)
                
                # If we have data to send to our local client, send it
                if len(remote_buffer):
                    print(f"[<==] Sending {len(remote_buffer)} bytes to localhost.")
                    client_socket.send(remote_buffer)
            else:
                print("[*] No initial data from remote.")
        
        # Now let's loop and read from local, send to remote, send to local
        loop_count = 0
        max_loops = 50  # Prevent infinite loops
        
        while loop_count < max_loops:
            loop_count += 1
            print(f"\n[*] Loop iteration {loop_count}")
            
            # Read from local host
            print("[*] Waiting for data from localhost...")
            local_buffer = receive_from(client_socket)
            
            if len(local_buffer):
                print(f"[==>] Received {len(local_buffer)} bytes from localhost.")
                hexdump(local_buffer)
                
                # Send it to our request handler
                local_buffer = request_handler(local_buffer)
                
                # Send off the data to the remote host
                try:
                    remote_socket.send(local_buffer)
                    print("[==>] Sent to remote.")
                except Exception as e:
                    print(f"[!] Failed to send to remote: {e}")
                    break
            else:
                print("[*] No data from localhost.")
            
            # Receive back the response
            print("[*] Waiting for response from remote...")
            remote_buffer = receive_from(remote_socket)
            
            if len(remote_buffer):
                print(f"[<==] Received {len(remote_buffer)} bytes from remote.")
                hexdump(remote_buffer)
                
                # Send to our response handler
                remote_buffer = response_handler(remote_buffer)
                
                # Send the response to the local socket
                try:
                    client_socket.send(remote_buffer)
                    print("[<==] Sent to localhost.")
                except Exception as e:
                    print(f"[!] Failed to send to localhost: {e}")
                    break
            else:
                print("[*] No data from remote.")
            
            # If no more data on either side after first exchange, close
            if loop_count > 1 and not len(local_buffer) and not len(remote_buffer):
                print("[*] No more data detected. Closing connections.")
                break
                
    except ConnectionRefusedError:
        print(f"[!] Connection refused by {remote_host}:{remote_port}")
    except Exception as e:
        print(f"[!] Exception in proxy_handler: {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            client_socket.close()
            remote_socket.close()
        except:
            pass
        print("[*] Connections closed.")


def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    """Main server loop to accept incoming connections"""
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((local_host, local_port))
    except Exception as e:
        print(f"[!!] Failed to listen on {local_host}:{local_port}")
        print(f"[!!] Error: {e}")
        print("[!!] Check for other listening sockets or correct permissions.")
        sys.exit(1)
    
    print(f"[*] Listening on {local_host}:{local_port}")
    print(f"[*] Forwarding to {remote_host}:{remote_port}")
    server.listen(5)
    
    while True:
        client_socket, addr = server.accept()
        
        # Print out the local connection information
        print(f"[==>] Received incoming connection from {addr[0]}:{addr[1]}")
        
        # Start a thread to talk to the remote host
        proxy_thread = threading.Thread(
            target=proxy_handler,
            args=(client_socket, remote_host, remote_port, receive_first)
        )
        proxy_thread.start()


def main():
    """Main function to parse arguments and start the proxy"""
    
    # Check command-line arguments
    if len(sys.argv[1:]) != 5:
        print("=" * 60)
        print("TCP Proxy Tool")
        print("=" * 60)
        print("\nUsage: python proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]")
        print("\nArguments:")
        print("  localhost     - Local address to listen on (e.g., 127.0.0.1 or 0.0.0.0)")
        print("  localport     - Local port to listen on")
        print("  remotehost    - Remote host to forward traffic to")
        print("  remoteport    - Remote port to forward traffic to")
        print("  receive_first - True/False: receive data from remote before sending")
        print("\nExample:")
        print("  python proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
        print("  python proxy.py 0.0.0.0 8080 www.google.com 80 False")
        print("=" * 60)
        sys.exit(1)
    
    # Setup local listening parameters
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    
    # Setup remote target
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])
    
    # This tells our proxy to connect and receive data before sending to the remote host
    receive_first = sys.argv[5]
    receive_first = True if "True" in receive_first else False
    
    # Now spin up our listening socket
    server_loop(local_host, local_port, remote_host, remote_port, receive_first)


if __name__ == '__main__':
    main()