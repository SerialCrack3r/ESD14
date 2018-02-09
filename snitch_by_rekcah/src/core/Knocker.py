#!/usr/bin/env python

import socket, sys

from random import randint
from struct import *

class Knocker :
    _key = 2293
    def __init__(self, server, port):
        self.obfuscatedPort = port ^ (Knocker._key * 25)    # Obfuscation of the port with the complete xor key
        self.port = port
        self.server = server

    def getRealPort(self):
        return self.port

    def getLocalIP(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))      # idealy We'd like to send a well formed packet to avoid detection
        except Exception as e :
            return "192.168.5.254"  # if we can't get the real ip adress then, let's send a rondom ip adress as source

        return s.getsockname()[0]

    def knock(self):
        # create a raw socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except Exception as e:
            print("Socket could not be created. Message : %s" % str(e))
            sys.exit()
        # tell kernel not to put in headers, since we are providing it
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # now start constructing the packet
        packet = ''

        source_ip = self.getLocalIP()
        dest_ip = self.server  # or socket.gethostbyname('www.google.com')

        # ip header fields
        ihl = 5
        version = 4
        tos = 0
        tot_len = 20 + 20  # python seems to correctly fill the total length, dont know how ??
        packetId = 54321  # Id of this packet
        frag_off = 0
        ttl = 255
        protocol = socket.IPPROTO_TCP
        check = 10  # python seems to correctly fill the checksum
        saddr = socket.inet_aton(source_ip)  # Spoof the source ip address if you want to
        daddr = socket.inet_aton(dest_ip)

        ihl_version = (version << 4) + ihl

        # the ! in the pack format string means network order
        ip_header = pack('!BBHHHBBH4s4s', ihl_version, tos, tot_len, packetId, frag_off, ttl, protocol, check, saddr, daddr)

        # tcp header fields
        source = randint(1, 65535)   # source port set randomly it doesn't matter we don't plan on receiving a response
        dest = self.obfuscatedPort  # destination port
        seq = 0
        ack_seq = 0
        doff = 5  # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
        # tcp flags
        fin = 0
        syn = 1
        rst = 0
        psh = 0
        ack = 0
        urg = 0
        window = socket.htons(5840)  # maximum allowed window size
        check = 0
        urg_ptr = 0

        offset_res = (doff << 4) + 0
        tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)

        # the ! in the pack format string means network order
        tcp_hdr = pack('!HHLLBBHHH', source, dest, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)

        # pseudo header fields
        source_address = socket.inet_aton(source_ip)
        dest_address = socket.inet_aton(dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_hdr)

        psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
        psh += tcp_hdr

        tcp_checksum = self.checksum(psh)

        # tcp_checksum = 0x2A3F

        # make the tcp header again and fill the correct checksum
        tcp_hdr = pack('!HHLLBBHHH', source, dest, seq, ack_seq, offset_res, tcp_flags, window, tcp_checksum, urg_ptr)

        # final full packet - syn packets dont have any data
        packet = ip_header + tcp_hdr

        # Send the packet finally - the port specified has no effect

        s.sendto(packet, (dest_ip, 0))      # Send our that'll hit the firewall, 3 times to make sure it works

        return


    # checksum functions needed for calculation checksum
    def checksum(self, msg):
        s = 0
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            w = (ord(chr(int(msg[i]))) << 8) + (ord(chr(int(msg[i + 1]))))
            s += w

        s = (s >> 16) + (s & 0xffff)
        # s = s + (s >> 16)
        # complement and mask to 4 byte short
        s = ~s & 0xffff
        return s
