import argparse
import socket
import threading


def connection_scan(target_ip, target_port):
    try:
        conn_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_socket.connect((target_ip, target_port))
        conn_socket.send(b'Banner_query\r\n')
        results = conn_socket.recv(100)
        print("[+] {}/tcp open".format(target_port))
        print("[+] -> {}".format(str(results)))
    except OSError:
        print("[-] {}/tcp closed".format(target_port))
    finally:
        conn_socket.close()


def port_scan(target, port_num):
    try:
        target_ip = socket.gethostbyname(target)
        print("[*] Scan result: {} on {}".format(target_ip, port_num))
        connection_scan(target_ip, int(port_num))
    except OSError:
        print("[^] Cannot resolve {}: invalid host".format(target))
        return


def argument_parser():
    parser = argparse.ArgumentParser(
        description="TCP scanner. Accepts a hostname/IP - identify services running")
    parser.add_argument("-o", "--host", nargs="?", help="Host IP address")
    parser.add_argument("-p", "--port", nargs="?",
                        default=(
                            ("20,21,22,23,25,53,67,68,80,110,123,137,138,139,156,161,179," +
                             "443,444,1433,1434,1453,1583,1723,1863,3050,3128,3306,3351,3389,3366,5432,8080,8332,15432,18332,18443")),
                        help="Port number or list, separeted, such as '25,80,8080'")
    var_args = vars(parser.parse_args())
    return var_args


if __name__ == '__main__':
    try:
        user_args = argument_parser()
        print(user_args)
        host = user_args["host"]
        port_list = user_args["port"].split(",")
        for port in port_list:
            port_scan(host, port)
    except AttributeError:
        print("Error")
