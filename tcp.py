from scapy.all import *

import queue
import random
import sys
import threading

# Script that fetches HTTP resources by building packets "manually" with Scapy.
#
# A few notes:
#
#
# 1) This script needs to be run with root privileges.
#
#
# 2) It works decently with google.com at the time of this writing. We don't
# implement any error checking/correction, or a lot of the details of TCP or
# HTTP, to say nothing of HTTPS, so it will probably fail with a lot of
# websites.
#
#
# 3) The kernel won't recognize our TCP connection, so may interfere by sending
# reset packets to the target. To fix this, block the kernel's packets.
#
# With iptables:
#
# sudo iptables -A OUTPUT -p tcp --sport 53437 --tcp-flags RST RST -j DROP
#
# (Where the specified --sport should match sport below).
#
#


TIMEOUT = 5  # Time to wait between packets before timing out, in seconds.


class TCPExchange():
    class Timeout(Exception):
        pass

    def __init__(self, dst='127.0.0.1', dport=80, sport=20):
        self.dst = dst
        self.dport = dport
        self.sport = sport

        self.response_queue = queue.Queue()

        self.next_ack = 0
        self.seq = random.randint(1000, 20000)
        self.initial_ack = 0

        # It's somewhat hard to get Scapy's send/receive functions to return
        # all relevant packets in a nonblocking way. Sniffing everything that
        # comes in from the given host/port and then we can sort it out.
        # Sniffing blocks - so do it in a separate thread and report back via a
        # queue.
        self.sniff_thread = threading.Thread(
            daemon=True, target=sniff, kwargs={
                'filter': 'src host {} and dst port {}'.format(dst, sport),
                'prn': self.get_sniffer(),
                'store': False
            }
        )

        self.sniff_thread.start()

    def get_packets(self):
        while True:
            try:
                r = self.response_queue.get(timeout=TIMEOUT)
            except queue.Empty:
                r = None
            if r is None:
                raise TCPExchange.Timeout('Timed out while receiving packets')

            if r == '':  # empty string indicates our sniffer thread is done
                break

            yield r

    def get_sniffer(self):
        # Returns a function that will serve as a first responder to packets
        # that come in.  The responder puts all packets in a queue so other
        # threads can get them.  Send ACKs in response to packets that need it.
        # When we get a FIN, ACK it, then call exit to kill the thread.

        # Responses could come in out of order, so if we don't know what to do
        # with one at first, we'll store it.
        responses = {}

        def _ack_and_queue(msg):
            responses[msg.seq] = msg

            while True:
                r = responses.get(self.next_ack)

                if not r:
                    break

                del responses[self.next_ack]

                self.response_queue.put(r)

                finished = r['TCP'].flags.F

                if 'Raw' in r:
                    payload = r['Raw']
                    self.next_ack = r.seq + len(payload)
                    if not finished:
                        self.send(flags='A')

                if finished:
                    self.next_ack += 1  # FIN increments ACK by 1
                    self.send(flags='FA')
                    self.response_queue.put('')
                    sys.exit(0)

        return _ack_and_queue

    def handshake(self):
        # Complete a TCP SYN/ACK handshake

        packets = sr1(self.make_packet(flags='S'), timeout=TIMEOUT, verbose=0)
        if not packets:
            raise TCPExchange.Timeout('Timed out during handshake')
        ans = packets[0]

        self.initial_ack = ans.seq
        self.next_ack = ans.seq + 1
        self.seq += 1  # Presence of syn flag increases sequence by 1

        flags = ans['TCP'].flags
        if not (flags.S and flags.A):
            print('Got unexpected response to our SYN')
            print('Response flags were: {}'.format(flags))
            sys.exit(1)

        self.send(flags='A')

    def make_packet(self, flags='S', payload=''):
        # Generate a packet with the correct destination, using the correct seq
        # and ack numbers, with the flags and payload specified.
        packet = IP(dst=self.dst)/TCP(
                flags=flags,
                ack=self.next_ack,
                seq=self.seq,
                dport=self.dport,
                sport=self.sport)

        if payload:
            packet = packet/payload

        return packet

    def request(self, resource):
        # Send an HTTP GET request to the target for the specified resource.
        self.handshake()
        payload = 'GET {}\r\n'.format(resource)
        self.send(flags='PA', payload=payload)

    def send(self, flags='S', payload=''):
        # Send a packet to the target with the specified flags and payload.
        send(self.make_packet(flags=flags, payload=payload), verbose=0)

        if payload:
            self.seq += len(payload)


print('\n')
e = TCPExchange(dst='google.com', dport=80, sport=53437)
e.request('/')

for r in e.get_packets():
    if 'Raw' in r:
        sys.stdout.write(str(r['Raw']))

print('\n')
