import socket
import struct
import codecs
class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


#return source_port, dest_port, data_length, checksum, data

class UdpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_length, checksum,data):
        self.src_port = src_port
        self.dst_port = dst_port
        self.data_length = data_length
        self.checksum = checksum
        self.data = data

def parse_udp_hacker(packet: bytes):
    header = packet[:8]
    data = packet[8:]
    source_port, dest_port,data_length, checksum = struct.unpack("!HHHH", header)
    return UdpPacket(source_port, dest_port, data_length, checksum, data)


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    destip = raw_ip_addr[:4]
    ips = ""
    for i in destip:
        byt = int.from_bytes([i], 'big')
        ips += str(byt) + "."
    ips = ips[:len(ips)-1]
    return ips





def parse_application_layer_packet(raw_data: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags =struct.unpack('!HHLLH', raw_data[:14])
    offset = (raw_data[12] >> 4) & 0x0F
    payload_data = raw_data[4*offset:]
    return TcpPacket(src_port, dest_port, offset, payload_data)


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    ihl = ip_packet[0] & 0x0F
    protocol = ip_packet[9]
    source_address = parse_raw_ip_addr(ip_packet[12:16])
    destination_address = parse_raw_ip_addr(ip_packet[16:20])
    payload = ip_packet[ihl*4:]
    return IpPacket(protocol, ihl, source_address, destination_address, payload)




def main():
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    packet_rec , address_ = sniffer.recvfrom(4096)
    hexlify_packet = codecs.getencoder(packet_rec)
    parsed_hexlify_packet = parse_network_layer_packet(hexlify_packet)
if __name__ == "__main__":
    main()
