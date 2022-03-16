from nest.topology import Node, Router, connect
from nest.engine.exec import exec_subprocess
import os
import time
import nest.config as config

from multiprocessing import Process


config.set_value("assign_random_names", False)
# ipv6 side
int_h1 = Node("h1")

r = Router("r")

# ipv4 side
out_h2 = Node("h2")


# "fc00:0000:0000:0000:0000:0000:0000:a012"

(h1_r, r_h1) = connect(int_h1, r)
(r_h2, h2_r) = connect(r, out_h2)

h1_r.set_address("64:ff9b::2/96")
r_h1.set_address("64:ff9b::3/96")

r_h2.set_address("10.0.1.1")
h2_r.set_address("10.0.1.2")


print("Running make")
print(os.system("sudo make"))
print(r_h1.name)
print("######## Make complete #####")

with r:
	os.system(f"sudo ./nat64 -i {r_h1.name} -4 10.0.1.0/24 -a fc00::/8")

print("nat64 running")

print("starting nc listen")
cmd = f"ip netns exec {out_h2.id} nc -lnvp 3000"
nc_listen_proc = Process(target=exec_subprocess, args=(cmd,))

print("starting wireshark")
cmd = f"ip netns exec {out_h2.id} wireshark"
wireshark_proc = Process(target=exec_subprocess, args=(cmd,))
wireshark_proc.start()
time.sleep(20)

print("sending nc")
with int_h1:
    os.system("nc -6 -v fc00:0000:0000:0000:0000:0000:0000:a012 3000")

time.sleep(3000)
