import socket
import argparse
import random
import struct

parser = argparse.ArgumentParser()
parser.add_argument('-t', '--timeout', type=int, default=5)
parser.add_argument('-r', '--max-retries', type=int, default=3)
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
randomNum = random.randint(0, 65535)
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
#clientSocket.settimeout(args.timeout)

clientSocket.send(packet)
received_data = clientSocket.recv(1024)
clientSocket.close()
#unpack DNS response header
print(received_data)
id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!H H H H H H", received_data)
print((id,flags,qdcount,ancount,nscount,arcount))

#unpack question
offset = 12
labelsReturned = []
cacheDict = {}
iterLabel = ""
while True:
    checkLen=struct.unpack_from("!b", received_data, offset)
    if checkLen[0] == 0:
        labelsReturned.append(iterLabel)
        cacheDict[offset-(len(iterLabel)+1)] = iterLabel
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
        cacheDict[offset-(len(iterLabel)+1)] = iterLabel
        offset += 1
        iterLabel = ""

qName = list(filter(lambda input: input != '', labelsReturned))
print(cacheDict)
qTypeTwo, qClassTwo = struct.unpack_from("!H H", received_data, offset)
offset += 4

print((qName,qTypeTwo, qClassTwo))

#name processing
labelsReturned = []
iterLabel = ""
print(offset)
while True:
    checkLen=struct.unpack_from("!b", received_data, offset)
    if checkLen[0] == 0:
        if iterLabel != '':
            labelsReturned.append(iterLabel)
        offset += 1
        break
    elif checkLen[0] & 15 == 12:
        offset -= 1
        checkLen=struct.unpack_from("!H", received_data, offset)
        ptrOffset = checkLen[0] & 16383
        offset += 2
        iterLabel=""
        for key in cacheDict:
            if key >= ptrOffset:
                labelsReturned.append(cacheDict[key])
    elif checkLen[0]>=65 and checkLen[0]<=90:
        iterLabel += chr(checkLen[0])
        offset += 1
    elif checkLen[0] >= 97 and checkLen[0] <= 122:
        iterLabel += chr(checkLen[0])
        offset += 1
    else:
        if iterLabel != '':
            labelsReturned.append(iterLabel)
        offset += 1
        iterLabel = ""

print(offset)

print(labelsReturned)
aType, aClass, aTtl, aRdlength,  = struct.unpack_from("!H H I H", received_data, offset)
offset += 10

print(aType)
print(aClass)
print(aTtl)
print(aRdlength)

# if aType == 1:
#     print("ip")

# elif aType == 2:
#     print("ns")
# elif aType == 15:
#     print("mx")
# elif aType == 80:
#     print("cname")














