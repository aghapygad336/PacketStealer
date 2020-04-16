import socket
import struct
import codecs
import binascii

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







def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    destip = raw_ip_addr[:4]
    ips = ""
    for i in destip:
        byt = int.from_bytes([i], 'big')
        ips += str(byt) + "."
    ips = ips[:len(ips)-1]
    return ips





def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    src_port_unpack = struct.unpack('!H', ip_packet_payload[:2])
    src_ip=src_port_unpack[0]
    dst_port_unpack = struct.unpack('!H', ip_packet_payload[2:4])
    dst_ip=dst_port_unpack[0]
    data_offset = (ip_packet_payload[12] >> 4) & (0x0F)
    payload = ip_packet_payload[ 4*data_offset:]
    
    return TcpPacket(src_ip, dst_ip, data_offset, payload)


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    protocol = ip_packet[9]
    ihl = ip_packet[0] &(0x0F)
    source_address=parse_raw_ip_addr(ip_packet[12:16])
    destination_address=parse_raw_ip_addr(ip_packet[16:20])
    payload = ip_packet[ihl*4:]
    return IpPacket(protocol, ihl, source_address, destination_address, payload)



def main():
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, 0x06)
    iface_name = "lo"
    sniffer.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    
    while True:
        
        packet_rec , address_ = sniffer.recvfrom(4096)
        # print("PACKET",packet_rec)
        parsed_hexlify_packet = parse_network_layer_packet(packet_rec)
        payload = parse_application_layer_packet(parsed_hexlify_packet.payload)
        try :
            print(payload.payload.decode("utf-8") )
        except:
            pass

        # print("*"*50)
        
if __name__ == "__main__":
    main()
