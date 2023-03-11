import socket
import logging
import pyshark


logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def get_local_ipv4_address() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    local_ipv4_address = s.getsockname()[0]
    s.close()
    logger.info(f'Got local IPv4 address: {local_ipv4_address}')
    return local_ipv4_address


def monitoring_network(
    packet_count: int = 1000, timeout: int = 60*60*24, interface: str = 'eth0'
) -> pyshark.LiveCapture:
    capture = pyshark.LiveCapture(interface=interface)
    capture.sniff(timeout=timeout, packet_count=packet_count)
    logger.info(f'Handled {packet_count} packages')
    return capture


def read_packages(
    target_ip: str, capture: pyshark.LiveCapture
) -> set:
    ips = set()

    for packet in capture:
        try:
            ip_layer = packet.layers[1]

            if str(ip_layer.dst) == target_ip or str(ip_layer.src) == target_ip:
                if str(ip_layer.dst) not in target_ip:
                    ips.add(ip_layer.dst)
                elif str(ip_layer.src) not in target_ip:
                    ips.add(ip_layer.src)

        except AttributeError:
            # Sometimes, ip layer hasn't dst or src attribute
            logger.warning('Expected AttributeError')

    return ips


if __name__ == '__main__':
    ips = set()
    local_ipv4_address = get_local_ipv4_address()
    while True:
        new_ips = read_packages(
            target_ip=local_ipv4_address, capture=monitoring_network()
        ) - ips
        logger.info(new_ips)
        ips = ips | new_ips
