#!/usr/bin/env python

import binascii
import socket
import argparse
import struct

# more detail: https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
# Packets
NEGOTIATE_PROTOCOL_REQUEST = binascii.unhexlify("00000085ff534d4272000000001853c00000000000000000000000000000fffe00004000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200")
SESSION_SETUP_REQUEST = binascii.unhexlify("00000088ff534d4273000000001807c00000000000000000000000000000fffe000040000dff00880004110a000000000000000100000000000000d40000004b000000000000570069006e0064006f007700730020003200300030003000200032003100390035000000570069006e0064006f007700730020003200300030003000200035002e0030000000")
TREE_CONNECT_REQUEST = binascii.unhexlify("00000060ff534d4275000000001807c00000000000000000000000000000fffe0008400004ff006000080001003500005c005c003100390032002e003100360038002e003100370035002e003100320038005c00490050004300240000003f3f3f3f3f00")
NAMED_PIPE_TRANS_REQUEST = binascii.unhexlify("0000004aff534d42250000000018012800000000000000000000000000088ea3010852981000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00")

# Arguments
parser = argparse.ArgumentParser(description="Detect if MS17-010 has been patched or not", formatter_class=argparse.RawTextHelpFormatter)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-i', '--ip', help='Single IP address to check')
parser.add_argument('-t', '--timeout', help="Timeout on connection for socket in seconds", default=1)
parser.add_argument('-v', '--verbose', help="Verbose output for checking of commands", action='store_true')

args = parser.parse_args()
ip = args.ip
timeout = args.timeout
verbose = args.verbose

def check_ip(ip):
    global negotiate_protocol_request, session_setup_request, tree_connect_request, trans2_session_setup, timeout, verbose

    # Connect to socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(float(timeout) if timeout else None)
    host = ip
    port = 445
    s.connect((host, port))

    # Send/receive negotiate protocol request
    if verbose:
        print(ip, "Sending negotiation protocol request")
    s.send(NEGOTIATE_PROTOCOL_REQUEST)
    s.recv(1024)

    # Send/receive session setup request
    if verbose:
        print(ip, "Sending session setup request")
    s.send(SESSION_SETUP_REQUEST)
    session_setup_response = s.recv(1024)

    # Extract user ID from session setup response
    user_id = session_setup_response[32:34]
    if verbose:
        print(ip, "User ID = %s" % struct.unpack("<H", user_id)[0])

    # Replace user ID in tree connect request packet
    modified_tree_connect_request = list(TREE_CONNECT_REQUEST)
    modified_tree_connect_request[32] = user_id[0]
    modified_tree_connect_request[33] = user_id[1]
    modified_tree_connect_request = "".join(modified_tree_connect_request)

    # Send tree connect request
    if verbose:
        print(ip, "Sending tree connect")
    s.send(modified_tree_connect_request)
    tree_connect_response = s.recv(1024)

    # Extract tree ID from response
    tree_id = tree_connect_response[28:30]
    if verbose:
        print(ip, "Tree ID = %s" % struct.unpack("<H", tree_id)[0])

    # Replace tree ID and user ID in named pipe trans packet
    modified_trans2_session_setup = list(NAMED_PIPE_TRANS_REQUEST)
    modified_trans2_session_setup[28] = tree_id[0]
    modified_trans2_session_setup[29] = tree_id[1]
    modified_trans2_session_setup[32] = user_id[0]
    modified_trans2_session_setup[33] = user_id[1]
    modified_trans2_session_setup = "".join(modified_trans2_session_setup)

    # Send trans2 sessions setup request
    if verbose:
        print(ip, "Sending named pipe")
    s.send(modified_trans2_session_setup)
    final_response = s.recv(1024)

    if final_response[9] == "\x05" and final_response[10] == "\x02" and final_response[11] == "\x00" and final_response[12] == "\xc0":      
        print "[+] [%s] is likely VULNERABLE to MS17-010" % (ip)
    else:
        print "[-] [%s] stays in safety" % ip

    s.close()

if ip:
    check_ip(ip)
