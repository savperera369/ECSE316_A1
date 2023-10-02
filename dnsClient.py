import sys
import socket
import argparse
import random
import struct

parser = argparse.ArgumentParser()
parser.add_argument('-t', '--timeout', type=str, default=5)
parser.add_argument('-r', '--max-retries', type=str, default=3)
parser.add_argument('-p', '--port', type=int, default=53)
group = parser.add_mutually_exclusive_group()
group.add_argument('-mx', action="store_true", default="False")
group.add_argument('-ns', action="store_true", default="False")
parser.add_argument('server', type=str)
parser.add_argument('name', type=str)

args = parser.parse_args()
print(args)
#construct request packet header
#id field
randomNum = random.randint(40000, 65535)
print(randomNum)
packet = struct.pack('>H', 34000)
#flags
packet += struct.pack('>H', 256)
#QDCOUNT
packet += struct.pack(">H", 1)
#ANCOUNT
packet += struct.pack(">H", 0)
#NSCount
packet += struct.pack(">H", 0)
#ARCOUNT
packet += struct.pack(">H", 0)

#add question to response packet
labels = args.name.split('.')

for label in labels:
    lenLabel = len(label)
    packet += struct.pack(">b", lenLabel)
    for character in label:
        packet += struct.pack("c", character.encode('utf-8'))

packet += struct.pack(">B", 0)

# type of query
if args.mx == True:
    packet += struct.pack(">H", 2)
elif args.ns == True:
    packet += struct.pack(">H", 15)
else:
    packet += struct.pack(">H", 1)

#QCLASS
packet += struct.pack(">H", 1)

print(packet)

server = ""
for character in args.server:
    if character != '@':
        server += character

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
clientSocket.connect((server, args.port))

#unpack DNS response header
id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!H H H H H H", packet)

#unpack question
offset = 12
labelsReturned = []
iterLabel = ""
while True:
    checkLen=struct.unpack_from("!b", packet, offset)
    if checkLen[0] == 0:
        labelsReturned.append(iterLabel)
        offset += 1
        break
    elif checkLen[0]>=65 and checkLen[0]<=90:
        iterLabel += chr(checkLen[0])
        offset += 1
    elif checkLen[0] >= 97 and checkLen[0] <= 122:
        iterLabel += chr(checkLen[0])
        offset += 1
    else:
        labelsReturned.append(iterLabel)
        offset += 1
        iterLabel = ""

questionName = filter(lambda input: input != '', labelsReturned)
qName = list(questionName)
print(qName)













