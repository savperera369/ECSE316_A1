import socket
import argparse
import random
import struct
import time

parser = argparse.ArgumentParser()
parser.add_argument('-t', '--timeout', type=int, default=5)
parser.add_argument('-r', '--maxretries', type=int, default=3)
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
packet = struct.pack('>H', randomNum)
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
rType = ""
if args.mx == True:
    packet += struct.pack(">H", 15)
    rType="MX"
elif args.ns == True:
    packet += struct.pack(">H", 2)
    rType="NS"
else:
    packet += struct.pack(">H", 1)
    rType="A"

#QCLASS
packet += struct.pack(">H", 1)

server = ""
for character in args.server:
    if character != '@':
        server += character

retries = 0
elapsedTime = 0
received_data = 0

while retries < args.maxretries:
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        clientSocket.connect((server, args.port))
        clientSocket.settimeout(args.timeout)

        startTime = time.time()
        clientSocket.send(packet)
        received_data = clientSocket.recv(2048)
        endTime = time.time()

        clientSocket.close()
        elapsedTime = endTime - startTime

        print(received_data)
        #unpack DNS response header
        id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!H H H H H H", received_data)

        error = flags & 15
        if error == 1:
            print("Format Error: Server unable to interpret query")
            break
        elif error == 2:
            print("Server failure. Unable to process query due to name server problem.")
            break
        elif error == 3:
            print("NOTFOUND")
            break
        elif error == 4:
            print("Not implemented: the name server does not support the requested kind of query")
            break
        elif error == 5:
            print("Refused: the name server refuses to perform the requested operation for policy reasons")
            break

        if (ancount + nscount + arcount) <= 0:
            print("NOTFOUND")
            break
        
        auth = ""
        if flags & 1024 == 1024:
            auth = "auth"
        else:
            auth = "nonauth"

        #unpack question
        offset = 12
        labelsReturned = []
        cacheDict = {}
        iterLabel = ""
        while True:
            checkLen=struct.unpack_from("!b", received_data, offset)
            if checkLen[0] == 0:
                if iterLabel != '':
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
            elif checkLen[0] >= 48 and checkLen[0] <= 57:
                iterLabel += chr(checkLen[0])
                offset += 1
            elif checkLen[0] == 45:
                iterLabel += chr(checkLen[0])
                offset += 1
            else:
                if iterLabel != '':
                    labelsReturned.append(iterLabel)
                    cacheDict[offset-(len(iterLabel)+1)] = iterLabel
                offset += 1
                iterLabel = ""

        qTypeTwo, qClassTwo = struct.unpack_from("!H H", received_data, offset)
        offset += 4

        #name processing
        labelsReturned = []
        iterLabel = ""
        lastLabelPtr = False
        while True:
            checkLen=struct.unpack_from("!b", received_data, offset)
            if checkLen[0] == 0:
                if iterLabel != '':
                    labelsReturned.append(iterLabel)
                if lastLabelPtr == False:
                    offset += 1
                break
            elif checkLen[0] & 192 == 192:
                if iterLabel != "":
                    labelsReturned.append(iterLabel)
                checkLen=struct.unpack_from("!H", received_data, offset)
                ptrOffset = checkLen[0] & 16383
                offset += 2
                iterLabel=""
                for key in cacheDict:
                    if key >= ptrOffset:
                        labelsReturned.append(cacheDict[key])
                lastLabelPtr = True
            elif checkLen[0]>=65 and checkLen[0]<=90:
                iterLabel += chr(checkLen[0])
                offset += 1
            elif checkLen[0] >= 97 and checkLen[0] <= 122:
                iterLabel += chr(checkLen[0])
                offset += 1
            elif checkLen[0] >= 48 and checkLen[0] <= 57:
                iterLabel += chr(checkLen[0])
                offset += 1
            elif checkLen[0] == 45:
                iterLabel += chr(checkLen[0])
                offset += 1
            else:
                if iterLabel != '':
                    labelsReturned.append(iterLabel)
                    lastLabelPtr = False
                offset += 1
                iterLabel = ""

        aType, aClass, aTtl, aRdlength = struct.unpack_from("!H H I H", received_data, offset)
        offset += 10

        #output section
        print("DNS client sending request for {}".format(args.name))
        print("Server: {}".format(args.server))
        print("Request Type: {}".format(rType))

        print("Answer received after {} seconds after {} retries".format(elapsedTime, retries))
        if(ancount>0):
            print("***Answer Section: {} records***".format(ancount))
            for i in range(ancount):
                if (i > 0):
                    labelsReturned = []
                    iterLabel = ""
                    lastLabelPtr = False
                    while True:
                        checkLen=struct.unpack_from("!b", received_data, offset)
                        if checkLen[0] == 0:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                            if lastLabelPtr == False:
                                offset += 1
                            break
                        elif checkLen[0] & 192 == 192:
                            if iterLabel != "":
                                labelsReturned.append(iterLabel)
                            checkLen=struct.unpack_from("!H", received_data, offset)
                            ptrOffset = checkLen[0] & 16383
                            offset += 2
                            iterLabel=""
                            for key in cacheDict:
                                if key >= ptrOffset:
                                    labelsReturned.append(cacheDict[key])
                            lastLabelPtr = True
                        elif checkLen[0]>=65 and checkLen[0]<=90:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 97 and checkLen[0] <= 122:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 48 and checkLen[0] <= 57:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] == 45:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        else:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                                lastLabelPtr = False
                            offset += 1
                            iterLabel = ""

                    aType, aClass, aTtl, aRdlength = struct.unpack_from("!H H I H", received_data, offset)
                    offset += 10

                if aType == 1:
                    ipBone, ipBtwo, ipBthree, ipBfour = struct.unpack_from("!B B B B", received_data, offset)
                    ipAddress = str(ipBone) + "." + str(ipBtwo) + "." + str(ipBthree) + "." + str(ipBfour)
                    print("IP\t{}\t\tTTL\t{}\t\tAA\t{}".format(ipAddress, aTtl, auth))

                elif aType == 2:
                    labelsReturned = []
                    iterLabel = ""
                    lastLabelPtr = False
                    while True:
                        checkLen=struct.unpack_from("!b", received_data, offset)
                        if checkLen[0] == 0:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                            if lastLabelPtr == False:
                                offset += 1
                            break
                        elif checkLen[0] & 192 == 192:
                            if iterLabel != "":
                                labelsReturned.append(iterLabel)
                            checkLen=struct.unpack_from("!H", received_data, offset)
                            ptrOffset = checkLen[0] & 16383
                            offset += 2
                            iterLabel=""
                            for key in cacheDict:
                                if key >= ptrOffset:
                                    labelsReturned.append(cacheDict[key])
                            lastLabelPtr = True
                            break
                        elif checkLen[0]>=65 and checkLen[0]<=90:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 97 and checkLen[0] <= 122:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 48 and checkLen[0] <= 57:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] == 45:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        else:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                                lastLabelPtr = False
                            offset += 1
                            iterLabel = ""
                    
                    nameServer = ""
                    for i in range(len(labelsReturned)):
                        nameServer += labelsReturned[i]
                        if i!=(len(labelsReturned)-1):
                            nameServer += "."
                    
                    print("NS Alias\t{}\t\tTTL\t{}\t\tAA\t{}".format(nameServer, aTtl, auth))

                elif aType == 15:
                    mxPreference = struct.unpack_from("!H", received_data, offset)
                    offset += 2
                    labelsReturned = []
                    iterLabel = ""
                    lastLabelPtr = False
                    while True:
                        checkLen=struct.unpack_from("!b", received_data, offset)
                        if checkLen[0] == 0:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                            if lastLabelPtr == False:
                                offset += 1
                            break
                        elif checkLen[0] & 192 == 192:
                            if iterLabel != "":
                                labelsReturned.append(iterLabel)
                            checkLen=struct.unpack_from("!H", received_data, offset)
                            ptrOffset = checkLen[0] & 16383
                            offset += 2
                            iterLabel=""
                            for key in cacheDict:
                                if key >= ptrOffset:
                                    labelsReturned.append(cacheDict[key])
                            lastLabelPtr = True
                            break
                        elif checkLen[0]>=65 and checkLen[0]<=90:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 97 and checkLen[0] <= 122:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 48 and checkLen[0] <= 57:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] == 45:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        else:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                                lastLabelPtr = False
                            offset += 1
                            iterLabel = ""
                    
                    nameServer = ""
                    for i in range(len(labelsReturned)):
                        nameServer += labelsReturned[i]
                        if i!=(len(labelsReturned)-1):
                            nameServer += "."
                    
                    print("MX Alias\t{}\t\tPreference\t{}\t\tTTL\t{}\t\tAA\t{}".format(nameServer, mxPreference[0], aTtl, auth))
            
                elif aType == 5:
                    labelsReturned = []
                    iterLabel = ""
                    lastLabelPtr = False
                    while True:
                        checkLen=struct.unpack_from("!b", received_data, offset)
                        if checkLen[0] == 0:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                            if lastLabelPtr == False:
                                offset += 1
                            break
                        elif checkLen[0] & 192 == 192:
                            if iterLabel != "":
                                labelsReturned.append(iterLabel)
                            checkLen=struct.unpack_from("!H", received_data, offset)
                            ptrOffset = checkLen[0] & 16383
                            offset += 2
                            iterLabel=""
                            for key in cacheDict:
                                if key >= ptrOffset:
                                    labelsReturned.append(cacheDict[key])
                            lastLabelPtr = True
                            break
                        elif checkLen[0]>=65 and checkLen[0]<=90:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 97 and checkLen[0] <= 122:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 48 and checkLen[0] <= 57:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] == 45:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        else:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                                lastLabelPtr = False
                            offset += 1
                            iterLabel = ""
                    
                    nameServer = ""
                    for i in range(len(labelsReturned)):
                        nameServer += labelsReturned[i]
                        if i!=(len(labelsReturned)-1):
                            nameServer += "."
                    
                    print("CNAME Alias\t{}\t\tTTL\t{}\t\tAA\t{}".format(nameServer, aTtl, auth))

        if(nscount>0):
            for i in range(arcount):
                labelsReturned = []
                iterLabel = ""
                lastLabelPtr = False
                while True:
                    checkLen=struct.unpack_from("!b", received_data, offset)
                    if checkLen[0] == 0:
                        if iterLabel != '':
                            labelsReturned.append(iterLabel)
                        if lastLabelPtr == False:
                            offset += 1
                        break
                    elif checkLen[0] & 192 == 192:
                        if iterLabel != "":
                            labelsReturned.append(iterLabel)
                        checkLen=struct.unpack_from("!H", received_data, offset)
                        ptrOffset = checkLen[0] & 16383
                        offset += 2
                        iterLabel=""
                        for key in cacheDict:
                            if key >= ptrOffset:
                                labelsReturned.append(cacheDict[key])
                        lastLabelPtr = True
                    elif checkLen[0]>=65 and checkLen[0]<=90:
                        iterLabel += chr(checkLen[0])
                        offset += 1
                    elif checkLen[0] >= 97 and checkLen[0] <= 122:
                        iterLabel += chr(checkLen[0])
                        offset += 1
                    elif checkLen[0] >= 48 and checkLen[0] <= 57:
                        iterLabel += chr(checkLen[0])
                        offset += 1
                    elif checkLen[0] == 45:
                        iterLabel += chr(checkLen[0])
                        offset += 1
                    else:
                        if iterLabel != '':
                            labelsReturned.append(iterLabel)
                            lastLabelPtr = False
                        offset += 1
                        iterLabel = ""

                aType, aClass, aTtl, aRdlength = struct.unpack_from("!H H I H", received_data, offset)
                offset += 10

                if aType == 1:
                    ipBone, ipBtwo, ipBthree, ipBfour = struct.unpack_from("!B B B B", received_data, offset)
                    ipAddress = str(ipBone) + "." + str(ipBtwo) + "." + str(ipBthree) + "." + str(ipBfour)

                elif aType == 2:
                    labelsReturned = []
                    iterLabel = ""
                    lastLabelPtr = False
                    while True:
                        checkLen=struct.unpack_from("!b", received_data, offset)
                        if checkLen[0] == 0:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                            if lastLabelPtr == False:
                                offset += 1
                            break
                        elif checkLen[0] & 192 == 192:
                            if iterLabel != "":
                                labelsReturned.append(iterLabel)
                            checkLen=struct.unpack_from("!H", received_data, offset)
                            ptrOffset = checkLen[0] & 16383
                            offset += 2
                            iterLabel=""
                            for key in cacheDict:
                                if key >= ptrOffset:
                                    labelsReturned.append(cacheDict[key])
                            lastLabelPtr = True
                            break
                        elif checkLen[0]>=65 and checkLen[0]<=90:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 97 and checkLen[0] <= 122:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 48 and checkLen[0] <= 57:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] == 45:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        else:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                                lastLabelPtr = False
                            offset += 1
                            iterLabel = ""
                    
                    nameServer = ""
                    for i in range(len(labelsReturned)):
                        nameServer += labelsReturned[i]
                        if i!=(len(labelsReturned)-1):
                            nameServer += "."

                elif aType == 15:
                    mxPreference = struct.unpack_from("!H", received_data, offset)
                    offset += 2
                    labelsReturned = []
                    iterLabel = ""
                    lastLabelPtr = False
                    while True:
                        checkLen=struct.unpack_from("!b", received_data, offset)
                        if checkLen[0] == 0:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                            if lastLabelPtr == False:
                                offset += 1
                            break
                        elif checkLen[0] & 192 == 192:
                            if iterLabel != "":
                                labelsReturned.append(iterLabel)
                            checkLen=struct.unpack_from("!H", received_data, offset)
                            ptrOffset = checkLen[0] & 16383
                            offset += 2
                            iterLabel=""
                            for key in cacheDict:
                                if key >= ptrOffset:
                                    labelsReturned.append(cacheDict[key])
                            lastLabelPtr = True
                            break
                        elif checkLen[0]>=65 and checkLen[0]<=90:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 97 and checkLen[0] <= 122:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 48 and checkLen[0] <= 57:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] == 45:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        else:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                                lastLabelPtr = False
                            offset += 1
                            iterLabel = ""
                    
                    nameServer = ""
                    for i in range(len(labelsReturned)):
                        nameServer += labelsReturned[i]
                        if i!=(len(labelsReturned)-1):
                            nameServer += "."
            
                elif aType == 5:
                    labelsReturned = []
                    iterLabel = ""
                    lastLabelPtr = False
                    while True:
                        checkLen=struct.unpack_from("!b", received_data, offset)
                        if checkLen[0] == 0:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                            if lastLabelPtr == False:
                                offset += 1
                            break
                        elif checkLen[0] & 192 == 192:
                            if iterLabel != "":
                                labelsReturned.append(iterLabel)
                            checkLen=struct.unpack_from("!H", received_data, offset)
                            ptrOffset = checkLen[0] & 16383
                            offset += 2
                            iterLabel=""
                            for key in cacheDict:
                                if key >= ptrOffset:
                                    labelsReturned.append(cacheDict[key])
                            lastLabelPtr = True
                            break
                        elif checkLen[0]>=65 and checkLen[0]<=90:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 97 and checkLen[0] <= 122:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 48 and checkLen[0] <= 57:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] == 45:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        else:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                                lastLabelPtr = False
                            offset += 1
                            iterLabel = ""
                    
                    nameServer = ""
                    for i in range(len(labelsReturned)):
                        nameServer += labelsReturned[i]
                        if i!=(len(labelsReturned)-1):
                            nameServer += "."

        if(arcount>0):
            print("***Additional Section: {} records***".format(arcount))
            for i in range(arcount):
                labelsReturned = []
                iterLabel = ""
                lastLabelPtr = False
                while True:
                    checkLen=struct.unpack_from("!b", received_data, offset)
                    if checkLen[0] == 0:
                        if iterLabel != '':
                            labelsReturned.append(iterLabel)
                        if lastLabelPtr == False:
                            offset += 1
                        break
                    elif checkLen[0] & 192 == 192:
                        if iterLabel != "":
                            labelsReturned.append(iterLabel)
                        checkLen=struct.unpack_from("!H", received_data, offset)
                        ptrOffset = checkLen[0] & 16383
                        offset += 2
                        iterLabel=""
                        for key in cacheDict:
                            if key >= ptrOffset:
                                labelsReturned.append(cacheDict[key])
                        lastLabelPtr = True
                    elif checkLen[0]>=65 and checkLen[0]<=90:
                        iterLabel += chr(checkLen[0])
                        offset += 1
                    elif checkLen[0] >= 97 and checkLen[0] <= 122:
                        iterLabel += chr(checkLen[0])
                        offset += 1
                    elif checkLen[0] >= 48 and checkLen[0] <= 57:
                        iterLabel += chr(checkLen[0])
                        offset += 1
                    elif checkLen[0] == 45:
                        iterLabel += chr(checkLen[0])
                        offset += 1
                    else:
                        if iterLabel != '':
                            labelsReturned.append(iterLabel)
                            lastLabelPtr = False
                        offset += 1
                        iterLabel = ""

                aType, aClass, aTtl, aRdlength = struct.unpack_from("!H H I H", received_data, offset)
                offset += 10

                if aType == 1:
                    ipBone, ipBtwo, ipBthree, ipBfour = struct.unpack_from("!B B B B", received_data, offset)
                    ipAddress = str(ipBone) + "." + str(ipBtwo) + "." + str(ipBthree) + "." + str(ipBfour)
                    print("IP\t{}\t\tTTL\t{}\t\tAA\t{}".format(ipAddress, aTtl, auth))

                elif aType == 2:
                    labelsReturned = []
                    iterLabel = ""
                    lastLabelPtr = False
                    while True:
                        checkLen=struct.unpack_from("!b", received_data, offset)
                        if checkLen[0] == 0:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                            if lastLabelPtr == False:
                                offset += 1
                            break
                        elif checkLen[0] & 192 == 192:
                            if iterLabel != "":
                                labelsReturned.append(iterLabel)
                            checkLen=struct.unpack_from("!H", received_data, offset)
                            ptrOffset = checkLen[0] & 16383
                            offset += 2
                            iterLabel=""
                            for key in cacheDict:
                                if key >= ptrOffset:
                                    labelsReturned.append(cacheDict[key])
                            lastLabelPtr = True
                            break
                        elif checkLen[0]>=65 and checkLen[0]<=90:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 97 and checkLen[0] <= 122:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 48 and checkLen[0] <= 57:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] == 45:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        else:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                                lastLabelPtr = False
                            offset += 1
                            iterLabel = ""
                    
                    nameServer = ""
                    for i in range(len(labelsReturned)):
                        nameServer += labelsReturned[i]
                        if i!=(len(labelsReturned)-1):
                            nameServer += "."
                    
                    print("NS Alias\t{}\t\tTTL\t{}\t\tAA\t{}".format(nameServer, aTtl, auth))

                elif aType == 15:
                    mxPreference = struct.unpack_from("!H", received_data, offset)
                    offset += 2
                    labelsReturned = []
                    iterLabel = ""
                    lastLabelPtr = False
                    while True:
                        checkLen=struct.unpack_from("!b", received_data, offset)
                        if checkLen[0] == 0:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                            if lastLabelPtr == False:
                                offset += 1
                            break
                        elif checkLen[0] & 192 == 192:
                            if iterLabel != "":
                                labelsReturned.append(iterLabel)
                            checkLen=struct.unpack_from("!H", received_data, offset)
                            ptrOffset = checkLen[0] & 16383
                            offset += 2
                            iterLabel=""
                            for key in cacheDict:
                                if key >= ptrOffset:
                                    labelsReturned.append(cacheDict[key])
                            lastLabelPtr = True
                            break
                        elif checkLen[0]>=65 and checkLen[0]<=90:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 97 and checkLen[0] <= 122:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 48 and checkLen[0] <= 57:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] == 45:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        else:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                                lastLabelPtr = False
                            offset += 1
                            iterLabel = ""
                    
                    nameServer = ""
                    for i in range(len(labelsReturned)):
                        nameServer += labelsReturned[i]
                        if i!=(len(labelsReturned)-1):
                            nameServer += "."
                    
                    print("MX Alias\t{}\t\tPreference\t{}\t\tTTL\t{}\t\tAA\t{}".format(nameServer, mxPreference[0], aTtl, auth))
            
                elif aType == 5:
                    labelsReturned = []
                    iterLabel = ""
                    lastLabelPtr = False
                    while True:
                        checkLen=struct.unpack_from("!b", received_data, offset)
                        if checkLen[0] == 0:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                            if lastLabelPtr == False:
                                offset += 1
                            break
                        elif checkLen[0] & 192 == 192:
                            if iterLabel != "":
                                labelsReturned.append(iterLabel)
                            checkLen=struct.unpack_from("!H", received_data, offset)
                            ptrOffset = checkLen[0] & 16383
                            offset += 2
                            iterLabel=""
                            for key in cacheDict:
                                if key >= ptrOffset:
                                    labelsReturned.append(cacheDict[key])
                            lastLabelPtr = True
                            break
                        elif checkLen[0]>=65 and checkLen[0]<=90:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 97 and checkLen[0] <= 122:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] >= 48 and checkLen[0] <= 57:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        elif checkLen[0] == 45:
                            iterLabel += chr(checkLen[0])
                            offset += 1
                        else:
                            if iterLabel != '':
                                labelsReturned.append(iterLabel)
                                lastLabelPtr = False
                            offset += 1
                            iterLabel = ""
                    
                    nameServer = ""
                    for i in range(len(labelsReturned)):
                        nameServer += labelsReturned[i]
                        if i!=(len(labelsReturned)-1):
                            nameServer += "."
                    
                    print("CNAME Alias\t{}\t\tTTL\t{}\t\tAA\t{}".format(nameServer, aTtl, auth))           
        break

    except socket.timeout as e:
        print("Socket Timeout: {}".format(e))
        retries += 1
    except socket.herror as e:
        print("There is an error related to the provided address.")
    except socket.gaierror as e:
        print("The provided host name is invalid.")
    except socket.error as e:
        print("There was an error creating the socket: {}".format(e))
        retries += 1
    
if retries == 3:
    print("Maximum number of retries exceeded.")













