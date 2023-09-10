import socket
import struct
import dns.resolver, dns.reversename  # Import the dnspython library
from binascii import hexlify

def reverse_dns_lookup(ip_address):
    try:

        addrs = dns.reversename.from_address(ip_address)

        # print(str(dns.resolver.resolve(addrs,"PTR")[0]))

        result = dns.resolver.resolve(addrs, 'PTR')
        return str(result[0])
    except dns.exception.DNSException:
        return "Reverse DNS lookup failed"

def main():
    # Create a raw socket for packet capture
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    
    # Network interface to capture packets from (replace 'eth0' with your interface)
    interface = 'eth0'
    
    observed_ips = set()  # To store unique observed IP addresses

    ctf_ips = {}  # To store IP addresses where CTF answers were found and their associated packet data
    ctf_data = {}  # To store IP addresses, CTF questions, answers, and associated packet data
    sum_of_ports = 2345

    try:
        # Bind the socket to the network interface
        s.bind((interface, 0))
        
        print(f"Capturing packets on interface {interface}...")

        while True:
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

            # Add observed IP addresses to the set
            observed_ips.add(source_ip)
            observed_ips.add(dest_ip)

            # Extract source and destination ports from TCP header (assuming it's TCP)
            if ip_header[9] == 6:  # Check if the protocol is TCP (IP header's 10th byte)
                tcp_header = packet[34:54]
                tcp = struct.unpack("!HH", tcp_header[:4])
                source_port = tcp[0]
                dest_port = tcp[1]
                print(f"Source Port: {source_port}, Destination Port: {dest_port}")
                
                
                # Question 1: Flag in a TCP Packet
                # Search for the keyword "Flag" in packet data
                packet_data = packet[54:]  # Adjust the offset based on your packet structure
                # packet_data = unicode(packet_data, errors='ignore')
                # print(packet_data.decode("utf-8"))
                # print(packet_data)
                if b"Flag" in packet_data and b"not the Flag" not in packet_data:
                    print("Question 1 Answer: Flag found in this TCP packet")
                    # print("Packet Data", packet_data)
                    # Store the packet data for this IP address
                    if source_ip in ctf_ips:
                        ctf_ips[source_ip].append(packet_data)
                    else:
                        ctf_ips[source_ip] = [packet_data]
                    
                    if 0 not in ctf_data:
                        ctf_data[0] = []
                    ctf_data[0].append(source_ip)

                # Question 2: My username is secret
                # Check if packet data contains the string "secret"
                if b"secret" in packet_data:
                    print("Question 2 Answer: Username 'secret' identified")
                    # print("Packet Data", packet_data)
                    # Store the packet data for this IP address
                    if source_ip in ctf_ips:
                        ctf_ips[source_ip].append(packet_data)
                    else:
                        ctf_ips[source_ip] = [packet_data]

                    if 1 not in ctf_data:
                        ctf_data[1] = []
                    ctf_data[1].append(source_ip)

                # Question 3: TCP checksum "0xcde1" with instructions in path
                # Check if TCP checksum matches the specified value
                # You need to extract the TCP checksum from the packet and compare it
                tcp_checksum = struct.unpack("!H", tcp_header[16:18])[0]  # Extract TCP checksum
                if tcp_checksum == 0xcde1 or b'PASSWORD' in packet_data:
                    print("Question 3 Answer: TCP checksum '0xcde1' identified")
                    # print("Packet Data", packet_data)
                    # Store the packet data for this IP address
                    if source_ip in ctf_ips:
                        ctf_ips[source_ip].append(packet_data)
                    else:
                        ctf_ips[source_ip] = [packet_data]


                    if 2 not in ctf_data:
                        ctf_data[2] = []
                    ctf_data[2].append(source_ip)
                    
                # Question 4: Device has IP Address "12.34.56.78"
                # Check if source or destination IP is "12.34.56.78"
                if source_ip == "12.34.56.78" or dest_ip == "12.34.56.78" or source_port == 2345 or dest_port == 2345:
                    print("Question 4 Answer: IP Address '12.34.56.78' identified")
                    # print("Packet Data", packet_data)
                    sum_of_ports = source_port + dest_port
                    # Store the packet data for this IP address
                    if source_ip in ctf_ips:
                        ctf_ips[source_ip].append(packet_data)
                        ctf_ips[source_ip].append(f",Sum of Ports:{sum_of_ports},")
                    else:
                        ctf_ips[source_ip] = [packet_data]
                        ctf_ips[source_ip].append(f",Sum of Ports:{sum_of_ports},")

                    

                    if 3 not in ctf_data:
                        ctf_data[3] = []
                    ctf_data[3].append(source_ip)
                    
                # Question 5: Come from localhost, requested a milkshake
                # Check if source IP is localhost and packet data contains "milkshake"
                if source_ip == "127.0.0.1" and b"milkshake" in packet_data:
                    print("Question 5 Answer: Came from localhost and requested 'milkshake'")
                    # print("Packet Data", packet_data)
                    # Store the packet data for this IP address
                    if source_ip in ctf_ips:
                        ctf_ips[source_ip].append(packet_data)
                    else:
                        ctf_ips[source_ip] = [packet_data]


                    if 4 not in ctf_data:
                        ctf_data[4] = []
                    ctf_data[4].append(source_ip)
                    
            # Print packet information
            # print(f"Source MAC: {source_mac}, Destination MAC: {dest_mac}")
            print(f"Source IP: {source_ip}, Destination IP: {dest_ip}")
            print("=" * 40)

    except KeyboardInterrupt:
        print("\nCapture stopped by the user.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    finally:
        s.close()

    print("Total IP Addresses observed", len(observed_ips))
    # Display unique observed IP addresses
    print("Observed IP Addresses:")
    for ip in observed_ips:
        print(ip, end=" , ")
    print()
    print("=" * 40)
    
    # Display IP addresses where CTF answers were found along with their packet data
    print("IP Addresses where CTF answers were found:")
    for i, l in ctf_data.items():
        print(f"Question{i+1}:")
        for ip in l:
            packets = ctf_ips[ip]
    # for ip, packets in ctf_ips.items():
            print(ip, end=" , ")
            print("Packet Data:")
            for packet_data in packets:
                print(packet_data)
        print("=" * 40)

if __name__ == "__main__":
    main()
