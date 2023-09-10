import socket
import struct
import subprocess
import time

def get_process_id_for_port(port):
    try:
        # Run the netstat command and capture both stdout and stderr
        result = subprocess.Popen(['netstat', '-tunp'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = result.communicate()
        
        # Process the captured stdout to find the process ID associated with the port
        output = stdout + stderr  # Combine stdout and stderr
        lines = output.split('\n')
        # print(output)
        for line in lines:
            if f":{port}" in line:
                parts = line.split()
                if len(parts) >= 7:
                    return parts[6]
    except Exception as e:
        print(f"Error while getting process ID: {str(e)}")
    return None

def main():
    # Create a raw socket for packet capture
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    
    # Network interface to capture packets from (replace 'eth0' with your interface)
    interface = 'eth0'
    
    process_ids = {}  # Dictionary to store port-process ID mappings
    ports_with_pids = set()  # Set to store ports with PIDs

    try:
        # Bind the socket to the network interface
        s.bind((interface, 0))
        
        print(f"Capturing packets on interface {interface} for 30 seconds...")
        print("Press Ctrl+C to exit.")

        start_time = time.time()
        capture_packets = True
        while time.time() - start_time < 30:
            if not capture_packets:
                break
            try:
                # Receive a packet and its address
                packet, addr = s.recvfrom(65535)

                # Extract Ethernet header (14 bytes)
                eth_header = packet[:14]
                eth = struct.unpack("!6s6sH", eth_header)

                # Extract IP header (20 bytes for IPv4)
                ip_header = packet[14:34]
                ip = struct.unpack("!12s4s4s", ip_header)

                # Extract source and destination IP addresses
                source_ip = socket.inet_ntoa(ip[1])
                dest_ip = socket.inet_ntoa(ip[2])

                # Extract source and destination ports from TCP header (assuming it's TCP)
                if ip_header[9] == 6:  # Check if the protocol is TCP (IP header's 10th byte)
                    tcp_header = packet[34:54]
                    tcp = struct.unpack("!HH", tcp_header[:4])
                    source_port = tcp[0]
                    dest_port = tcp[1]
                    print(f"Source Port: {source_port}, Destination Port: {dest_port}")

                    # Link packet data to process ID using the destination port
                    if dest_port not in process_ids:
                        process_id = get_process_id_for_port(dest_port)
                        if process_id:
                            process_ids[dest_port] = process_id
                            ports_with_pids.add(dest_port)
                    # Link packet data to process ID using the source port
                    if dest_port not in process_ids:
                        process_id = get_process_id_for_port(source_port)
                        if process_id:
                            process_ids[source_port] = process_id
                            ports_with_pids.add(source_port)
                    print("Process Id:", process_id)
                    print("=" * 40)
            except KeyboardInterrupt:
                print("\nStopped capturing packets.")
                capture_packets = False
        while True:
            try:
                port = int(input("Enter a port number to get the corresponding process ID (Ctrl+C to exit): "))
                if port in process_ids:
                    print(f"Process ID for Port {port}: {process_ids[port]}")
                else:
                    print(f"No process found for Port {port}")
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except ValueError:
                print("Invalid input. Please enter a valid port number.")
        print("Ports with associated PIDs:")
        for port in ports_with_pids:
            print(f"Port {port}: Process ID {process_ids[port]}")
    except KeyboardInterrupt:
        print("\nCapture stopped by the user.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    finally:
        s.close()

if __name__ == "__main__":
    main()
