import time
from scapy.all import *

def craft_and_send_packet(src_ip, dst_ip, custom_payload):
    # Craft the IP layer
    ip = IP(src=src_ip, dst=dst_ip)

    # Craft the ICMP layer
    icmp = ICMP()

    # Add custom payload
    payload = Raw(load=custom_payload)

    # Combine the layers
    packet = ip/icmp/payload
    start_time = time.time()
    # Send the packet and receive the response
    answered, unanswered = sr(packet, timeout=2)  # Adjust timeout as needed

    # Calculate round trip time (RTT)
    rtt = (time.time() - start_time) * 1000  # Convert to milliseconds

    # Handle the answered packets
    for sent, received in answered:
        # Mimic the ping output
        print(f"{len(received)} bytes from {received.src}: icmp_seq={icmp.seq} ttl={received.ttl} time={rtt:.2f} ms")
    # Handle the answered packets
    for sent, received in answered:
        # Print the summary of the response
        print(received.summary())


    # Optionally, handle the unanswered packets
    # for sent in unanswered:
    #     print(sent.summary() + " was unanswered")

# Example usage
craft_and_send_packet("192.168.179.139", "192.168.179.144", "MG")


