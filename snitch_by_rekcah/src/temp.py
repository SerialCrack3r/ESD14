#!/usr/bin/env python

import base64, string, secrets
import sys


# if sys.platform == 'win32':
#   import win32_sysinfo as sysinfo
# elif sys.platform == 'darwin':
#   import mac_sysinfo as sysinfo
# elif 'linux' in sys.platform:
#   import linux_sysinfo as sysinfo
#etc
import binascii
import subprocess
import socket
import psutil

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("", 6666))

print(s.getsockname()[0])

s.close()

print("xor %d " % (5010 ^ 57325))

print("rev xor %d " % (52351 ^ 57325))

print("Vir mem -> %s" % str(psutil.virtual_memory()))

print("%s" % (''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))))

print("-----------")
op = subprocess.Popen(["cd"], shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
if op:
    output = str(op.stdout.read())
    # sockt.send(str(output).encode(ENCODING))
    print("[cd] ---> [%s]" % (str(output)))
else:
    error = str(op.stderr.read())
    # sockt.send(str(error).encode(ENCODING))
    print("[cd] ---> [%s]" % (str(error)))
print("-----------")


# print('Memory available:' + sysinfo.memory_available())


info = {"architecture": "arch", "system": "sys", "uname": "una", "release": "rel", "sys_ver": "ver"}

print(info)

# with open("snitch_by_rekcah.zip", "rb") as file :
#     buff = file.read(4096)
#     while buff :
#         temp = "nanoooo ".encode("utf-8") + buff
#         print(temp.split(" ".encode("utf-8"))[0].decode("utf-8"))
#         buff = file.read(4096)

string = "test string"



print(string.split("test"))
print("-----------")
string = "this is string example....wow!!!"
encoded = base64.b64encode(b"data to be encoded")
print(encoded)
