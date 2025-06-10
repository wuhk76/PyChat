import os
import time
import subprocess
from scapy.all import *
class Pychat:
    def __init__(self):
        self.dest = ''
        self.iface = ''
    def send(self, message):
        term = subprocess.run(f'ip link show {self.iface}', capture_output = True, text = True, shell = True)
        term = term.stdout.split('radiotap')
        term = term[1]
        term = term.split('brd')
        term = term[0]
        mac = term.strip()
        packet = RadioTap() / Dot11(type = 2, subtype = 0, addr1 = self.dest, addr2 = mac, addr3 = mac) / LLC() / SNAP() / Raw(load =message)
        sendp(packet, iface = self.iface, verbose = False)
    def receive(self):
        term = subprocess.run(f'ip link show {self.iface}', capture_output = True, text = True, shell = True)
        term = term.stdout.split('radiotap')
        term = term[1]
        term = term.split('brd')
        term = term[0]
        mac = term.strip()
        rmessage = ''
        while len(rmessage) < 1:
            packet = sniff(iface = self.iface, count = 1)
            packet = packet[0]
            if packet.haslayer(Raw) and packet.haslayer(Dot11) and packet.addr1 == mac:
                rmessage = packet[Raw]
                rmessage = rmessage.load.decode('utf-8', errors = 'ignore')
        return rmessage
    def dialup(self, dest, iface):
        self.dest = dest
        self.iface = iface
        print(f'Connected to {self.dest} on interface {self.iface}')
pychat = Pychat()
pychat.dialup(input('Enter destination MAC address: '), input('Enter interface name: '))
command = ''
running = True
while running:
    message = input('(you):')
    if message == ':q':
        pychat.send(' ')
        running = False
        break
    elif message == ':r':
        pychat.send(' ')
        print(f'({pychat.dest}):{pychat.receive()}')
    elif message == ':s':
        pychat.send(input('(you):'))
    elif message == ':rr':
        while running:
            print(f'({pychat.dest}):{pychat.receive()}')
            time.sleep(1)
    elif message == ':rs':
        while running:
            pychat.send(input('(you):'))
            time.sleep(1)
    elif message == ':fr':
        pychat.send(' ')
        path = os.path.dirname(__file__)
        rname = pychat.receive()
        time.sleep(1)
        with open(f'{path}/{rname}', 'x') as file:
            file.write(pychat.receive())
        print(f'({pychat.dest}):{rname}')
    elif message[0:3] == ':fs':
        path = message.split(' ')
        path = path[1]
        tname = path.split('/')
        tname = tname[-1]
        with open(f'{path}', 'r') as file:
            data = file.read()
        pychat.send(tname)
        time.sleep(1)
        pychat.send(data)
    else:
        pychat.send(message)
        print(f'({pychat.dest}):{pychat.receive()}')