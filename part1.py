import socket
import struct
import dns.resolver, dns.reversename  # Import the dnspython library

def reverse_dns_lookup(ip_address):
    try:

        addrs = dns.reversename.from_address(ip_address)
        # addrs = ip_address
        # print(str(dns.resolver.resolve(addrs,"PTR")[0]))

        result = dns.resolver.resolve(addrs, 'PTR')
        return str(result[0])
    except dns.exception.DNSException:
        return "Reverse DNS lookup failed"

def get_ip_address():
    try:
        # Create a socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Connect to a remote server (doesn't have to be a real server)
        s.connect(("8.8.8.8", 80))  # Using Google's DNS server
        
        # Get the local IP address from the socket's connection
        ip_address = s.getsockname()[0]
        
        # Close the socket
        s.close()
        
        return ip_address
    except Exception as e:
        print(f"Error while fetching IP address: {str(e)}")
        return None



def main():
    # fetch this device's ip
    my_ip = get_ip_address()
    # Create a raw socket for packet capture
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    
    # Network interface to capture packets from (replace 'eth0' with your interface)
    interface = 'eth0'
    
    observed_ips = set()  # To store unique observed IP addresses
    tcp_flows = set()
    tcp_flows_list = []
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

            

            # Extract source and destination ports from TCP header (assuming it's TCP)
            if ip_header[9] == 6:  # Check if the protocol is TCP (IP header's 10th byte)

                # Extract source and destination IP addresses
                source_ip = socket.inet_ntoa(ip[1])
                dest_ip = socket.inet_ntoa(ip[2])
                
                # Add observed IP addresses to the set
                observed_ips.add(source_ip)
                observed_ips.add(dest_ip)

                tcp_header = packet[34:54]
                tcp = struct.unpack("!HH", tcp_header[:4])
                # print("TCP",tcp, len(packet))
                source_port = tcp[0]
                dest_port = tcp[1]
                print(f"Source Port: {source_port}, Destination Port: {dest_port}")
                if source_ip == my_ip:
                    tcp_flows.add((source_ip, source_port, dest_ip, dest_port))
                    tcp_flows_list.append((source_ip, source_port, dest_ip, dest_port))
                # elif dest_ip == "10.0.2.15":
                #     tcp_flows.add(( dest_ip, dest_port, source_ip, source_port))
                #     tcp_flows_list.append(( dest_ip, dest_port, source_ip, source_port))
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

    
    print(f"My device's IP addr after ifconfig: {my_ip}")
    print("Number of flows:", len(tcp_flows))
    # print("Number of flows:", len(tcp_flows_list))
    print("Unique flows are:")
    for i in tcp_flows:
        print(i, end=" , ")
    print()
    print("Total IP Addresses observed", len(observed_ips))
    # Display unique observed IP addresses
    print("Observed IP Addresses:")
    for ip in observed_ips:
        print(ip, end=" , ")
    print()
    print("=" * 40)
    # Reverse DNS lookup for selected 5 IP addresses
    print("Sample DNS lookup for 8.8.8.8")
    print(f"Reverse DNS lookup result for 8.8.8.8:", reverse_dns_lookup("8.8.8.8"))
    print("Reverse DNS lookup for observed 5 IPs if possible")
    # for i in range(len(5)):
    j = 0
    k = 0
    for i in observed_ips:
        # selected_ip = input("Enter an IP address for reverse DNS lookup: ")
        # if selected_ip not in observed_ips:
        #     i=i-1
        #     print("IP not observed")
        #     continue
        selected_ip = i
        result = reverse_dns_lookup(selected_ip)
        k += 1
        # print(k, len(observed_ips), j, end=" ")
        if result != "Reverse DNS lookup failed" or k>=len(observed_ips)-5+j:
            print(f"Reverse DNS lookup result for {selected_ip}: {result}")
            j += 1
        if j>=5: 
            break

        # try:
        #     hostname, _, _ = socket.gethostbyaddr(selected_ip)
        #     print(f"Reverse DNS lookup result for {selected_ip}: {hostname}")
        # except socket.herror:
        #     print(f"Reverse DNS lookup failed for {selected_ip}.")

if __name__ == "__main__":
    main()
