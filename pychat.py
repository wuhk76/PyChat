import os
import time
import subprocess
from scapy.all import *
from cryptography.fernet import Fernet as fernet

class Pychat:

    def __init__(self):
        self.dest = ''
        self.iface = ''
        self.key = ''

    def send(self, message):
        if self.key != '':
            cipher = fernet(self.key)
            message = cipher.encrypt(message.encode('utf-8', errors = 'ignore'))
        term = subprocess.run(f'ip link show {self.iface}', capture_output = True, text = True, shell = True)
        term = term.stdout.split('radiotap')
        term = term[1]
        term = term.split('brd')
        term = term[0]
        mac = term.strip()
        packet = RadioTap() / Dot11(type = 2, subtype = 0, addr1 = self.dest, addr2 = mac, addr3 = mac) / LLC() / SNAP() / Raw(load = message)
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
        if self.key != '':
            cipher = fernet(self.key)
            rmessage = cipher.decrypt(rmessage.load).decode()
        else:
            rmessage = rmessage.load.decode('utf-8', errors = 'ignore')
        return rmessage

    def dialup(self, dest, iface, key):
        self.dest = dest
        self.iface = iface
        self.key = key.encode() if len(key) > 0 else key
        print(f'Connected to {self.dest} on interface {self.iface}')

pychat = Pychat()
pychat.dialup(input('Enter destination MAC address: '), input('Enter interface name: '), input('Enter encryption key (leave blank for no encryption): '))
print('')
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
    elif message[0:2] == ':s':
        info = message.split(' ')
        del info[0]
        info = ' '.join(info)
        pychat.send(info)
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
        rpath = os.path.dirname(__file__)
        rname = pychat.receive()
        time.sleep(2)
        with open(f'{rpath}/{rname}', 'x') as rfile:
            rfile.write(pychat.receive())
        print(f'({pychat.dest}):{rname}')
    elif message[0:3] == ':fs':
        tpath = message.split(' ')
        tpath = tpath[1]
        tname = tpath.split('/')
        tname = tname[-1]
        with open(f'{tpath}', 'r') as tfile:
            data = tfile.read()
        pychat.send(tname)
        time.sleep(2)
        pychat.send(data)
    else:
        pychat.send(message)
        print(f'({pychat.dest}):{pychat.receive()}')