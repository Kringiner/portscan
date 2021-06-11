import socket
import threading
import argparse
import packageFactory
import warnings

print_lock = threading.Lock()

recognizers = [(packageFactory.build_smtp_packet, packageFactory.is_smtp_package, "SMTP"),
               (packageFactory.build_pop3_packet, packageFactory.is_pop3_package, "POP3"),
               (packageFactory.build_dns_package, packageFactory.is_dns_package, "DNS"),
               (packageFactory.build_ntp_packet, packageFactory.is_ntp_package, "NTP"),
               (packageFactory.build_imap_packet, packageFactory.is_imap_packet, "IMAP")
               ]


def scan_tcp_port(ip, port):
    sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_connect = sock_tcp.connect_ex((ip, port))
    if tcp_connect == 0:
        with print_lock:
            print('TCP port :', port, ' is open', end=' ')
            application_layer = scan_application_layer(sock_tcp)
            print(application_layer)
    sock_tcp.close()


def scan_application_layer(sock):
    for builder, recognizer, answer in recognizers:
        try:
            sock.settimeout(0.05)
            sock.send(builder())
            response = sock.recv(2048)
            if recognizer(response):
                return answer
        except:
            pass
    return ""


def scan_udp_port(ip, port):
    sock_upd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_connect = sock_upd.connect_ex((ip, port))
    if udp_connect == 0:
        with print_lock:
            print('UDP port :', port, ' is open', end=' ')
            application_layer = scan_application_layer(sock_upd)
            print(application_layer)
    sock_upd.close()


if __name__ == '__main__':
    warnings.filterwarnings("ignore")
    help_text = "usage: portscan.py host [-h] [-t] [-u] [-p PORTS PORTS]"
    parser = argparse.ArgumentParser()
    parser.add_argument('host')
    parser.add_argument('-t', action='store_true')
    parser.add_argument('-u', action='store_true')
    parser.add_argument('-p', '--ports', nargs=2, type=int)
    args = parser.parse_args()
    if args.t == False and args.u == False:
        print('Нужно выбрать хотя бы один ключ из -u или -t')
        print(help_text)
    elif len(args.ports) != 2 or args.ports[0] < 0 or args.ports[1] < 0 or args.ports[0] >= args.ports[1]:
        print('Неверно указаны или не указаны порты для сканирования')
        print(help_text)
    else:
        start, stop = args.ports[0], args.ports[1]
        pool = []
        if args.t:
            for port in range(start, stop + 1):
                thread = threading.Thread(target=scan_tcp_port, args=(args.host, port))
                pool.append(thread)
                thread.start()
        if args.u:
            for port in range(start, stop + 1):
                thread = threading.Thread(target=scan_udp_port, args=(args.host, port))
                pool.append(thread)
                thread.start()
        for i in pool:
            i.join()
