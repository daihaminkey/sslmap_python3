#!/usr/bin/env python
# sslmap_python3.py v0.3.1 - Lightweight TLS/SSL cipher suite scanner.
#             * Uses custom TLS/SSL query engine for increased reliability/speed
#               (No need for third-party libraries such as OpenSSL)
#             * Tests for 200+ known cipher suites.
#             * Capable of discovering undocumented cipher suites.
#             * Advises on cipher suite security based on Protocol, Key Exchange,
#               Authentication, Encryption algorithm, and other parameters.
#             * Configurable handshake versions (e.g. TLSv1.1, SSLv2.0)
# usage: sslmap_python3.py --host gmail.com --port 443
#        sslmap_python3.py --help
#
# author: iphelix
# update: Dr_Ciphers - iosifidise@gmail.com
# python3 port: daihaminkey - daihaminkey@icloud.com

import socket
import binascii
import sys
import csv
from optparse import OptionParser
from ciphers import cipher_suites

# Standard TLS/SSL handshake
handshake_pkts = {
    "TLS v1.3": b'\x80\x2c\x01\x03\x04\x00\x03\x00\x00\x00\x20',
    "TLS v1.2": b'\x80\x2c\x01\x03\x03\x00\x03\x00\x00\x00\x20',
    "TLS v1.1": b'\x80\x2c\x01\x03\x02\x00\x03\x00\x00\x00\x20',
    "TLS v1.0": b'\x80\x2c\x01\x03\x01\x00\x03\x00\x00\x00\x20',
    "SSL v3.0": b'\x80\x2c\x01\x03\x00\x00\x03\x00\x00\x00\x20',
    "SSL v2.0": b'\x80\x2c\x01\x00\x02\x00\x03\x00\x00\x00\x20'
}

# NULL handshake challenge string
challenge = b'\x00' * 32

results = dict()

verbose = False


def load_ciphers(filename):
    global cipher_suites

    if verbose:
        print("[*] Loading custom cipher suite database")
    cipher_suites = dict()
    reader = csv.reader(open(filename, "r"))
    for cipher_id, name, protocol, kx, au, enc, bits, mac, kxau_strength, enc_strength, overall_strength in reader:
        if cipher_id != "id":
            cipher_suites[cipher_id] = {
                "name": name,
                "protocol": protocol,
                "kx": kx,
                "au": au,
                "enc": enc,
                "bits": bits,
                "mac": mac,
                "kxau_strength": kxau_strength,
                "enc_strength": enc_strength,
                "overall_strength": overall_strength
            }


def check_cipher(cipher_id, host, port, handshake="TLS"):
    handshake_pkt = handshake_pkts[handshake]

    cipher = binascii.unhexlify(cipher_id)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((host, port))
    except socket.error as e:
        print("[!] Could not connect to target host: {msg}".format(msg=e))
        s.close()
        sys.exit(1)

    bt = handshake_pkt + cipher + challenge

    s.send(bt)

    try:
        data = s.recv(1)
    except socket.error:
        s.close()
        return False

    # TLS/SSLv3 Server Hello
    if data == b'\x16':
        state = True   # Server Hello Code
    elif data == b'\x15':
        state = False  # Server Alert Code

    # SSLv2 Server Hello
    else:
        s.recv(8)
        data = s.recv(2)
        if data == b'\x00\x03':
            state = True  # Server Matching Cipher Length
        else:
            state = False

    s.close()
    return state


def print_cipher(cipher_id):
    if cipher_id in cipher_suites:
        # Display output
        print("[+] {name} (0x{id})".format(name=cipher_suites[cipher_id]['name'], id=cipher_id))
        if verbose: 
            print("\tSpecs: Kx={kx}, Au={au}, Enc={enc}, Bits={bits}, Mac={mac}".format(
                kx=cipher_suites[cipher_id]['kx'],
                au=cipher_suites[cipher_id]['au'],
                enc=cipher_suites[cipher_id]['enc'],
                bits=cipher_suites[cipher_id]['bits'],
                mac=cipher_suites[cipher_id]['mac']))
            print("\tScore: Kx/Au={kx_au_strength}, Enc/MAC={enc_strength}, Overall={overall_strength}".format(
                kx_au_strength=cipher_suites[cipher_id]['kxau_strength'],
                enc_strength=cipher_suites[cipher_id]['enc_strength'],
                overall_strength=cipher_suites[cipher_id]['overall_strength']))

        if cipher_suites[cipher_id]['overall_strength'] not in results:
            results[cipher_suites[cipher_id]['overall_strength']] = list()
        results[cipher_suites[cipher_id]['overall_strength']].append(cipher_id)
    else: 
        print("[+] Undocumented cipher (0x{id})".format(id=cipher_id))
        if "UNKNOWN" not in results:
            results["UNKNOWN"] = list()
        results["UNKNOWN"].append(cipher_id)


def generate_report():
    print("\n{line} Scan Results {line}".format(line="-"*20))
    for classification in results:
        print("The following cipher suites were rated as {cls}:".format(cls=classification))
        for cipher_id in results[classification]:
            print(cipher_suites[cipher_id]['name'])
        print("")


def scan_fuzz_ciphers(host, port, handshakes):
    print("[*] Fuzzing {h}:{p} for all possible cipher suite identifiers.".format(h=host, p=port))
    for handshake in handshakes:
        if verbose:
            print("[*] Using {hs} handshake...".format(hs=handshake))
        for i in range(0, 16777215):
            cipher_id = '%06x' % i
            if check_cipher(cipher_id, host, port):
                print_cipher(cipher_id)


def scan_known_ciphers(host, port, handshakes):
    print("[*] Scanning {h}:{p} for {length} known cipher suites.".format(h=host, p=port, length=len(cipher_suites)))
    for handshake in handshakes:

        if verbose:
            print("[*] Using {hs} handshake.".format(hs=handshake))
        for cipher_id in cipher_suites.keys():
            if check_cipher(cipher_id, host, port, handshake):
                print_cipher(cipher_id)


if __name__ == '__main__':
    print(r"""

            | |  version 0.3.1
     ___ ___| |
    / __/ __| | '_ ` _ \ / _` | '_ \
    \__ \__ \ | | | | | | (_| | |_) |
    |___/___/_|_| |_| |_|\__,_| .__/
                              | |    
      iphelix@thesprawl.org   |_|
         updates: daihaminkey@icloud..com
""")

    # Parse scan parameters
    parser = OptionParser()
    parser.add_option("--host", dest="host", help="host",  metavar="gmail.com")
    parser.add_option("--port", dest="port", help="port", default=443, type="int", metavar="443")
    parser.add_option("--fuzz",  action="store_true", dest="fuzz",  default=False, help="fuzz all possible cipher values (takes time)")
    parser.add_option("--tls1",  action="store_true", dest="tls1",  default=False, help="use TLS v1.0 handshake")
    parser.add_option("--tls11", action="store_true", dest="tls11", default=False, help="use TLS v1.1 handshake")
    parser.add_option("--tls12", action="store_true", dest="tls12", default=False, help="use TLS v1.2 handshake")
    parser.add_option("--tls13", action="store_true", dest="tls13", default=False, help="use TLS v1.3 handshake (future use)")
    parser.add_option("--ssl3",  action="store_true", dest="ssl3",  default=False, help="use SSL3 handshake")
    parser.add_option("--ssl2",  action="store_true", dest="ssl2",  default=False, help="use SSL2 handshake")
    parser.add_option("--verbose", action="store_true", dest="verbose",  default=False, help="enable verbose output")
    parser.add_option("--db", dest="db", help="external cipher suite database. DB Format: cipher_id,name,protocol,Kx,Au,Enc,Bits,Mac,Auth Strength,Enc Strength,Overall Strength", metavar="ciphers.csv")
    (options, args) = parser.parse_args()

    # Perform checks on user input
    if not options.host: 
        parser.print_help()
        sys.exit(1)
    
    else:
        HOST = options.host

    if options.verbose:
        verbose = True

    if options.db:
        load_ciphers(options.db)

    # Handshake selection
    available_handshakes = list()
    if options.tls13:
        available_handshakes.append("TLS v1.3")  # For future use and fuzzing
    if options.tls12:
        available_handshakes.append("TLS v1.2")
    if options.tls11:
        available_handshakes.append("TLS v1.1")
    if options.tls1:
        available_handshakes.append("TLS v1.0")
    if options.ssl3:
        available_handshakes.append("SSL v3.0")
    if options.ssl2:
        available_handshakes.append("SSL v2.0")

    if not available_handshakes:
        available_handshakes = ("TLS v1.0", "SSL v3.0")

    # Scan known ciphers by default, optionally fuzz all possible cipher suite ids
    if options.fuzz:
        scan_fuzz_ciphers(options.host, options.port, available_handshakes)
    else:
        scan_known_ciphers(options.host, options.port, available_handshakes)

    if results:
        generate_report()
