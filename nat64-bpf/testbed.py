import os
import time
from multiprocessing import Process

import nest.config as config
from nest.engine.exec import exec_subprocess
from nest.topology import Node, Router, connect

config.set_value("assign_random_names", False)
# ipv6 side
int_h1 = Node("h1")

r = Router("r")

# ipv4 side
out_h2 = Node("h2")


# "fc00:0000:0000:0000:0000:0000:0a00:0102"

(h1_r, r_h1) = connect(int_h1, r, "h1-r", "r-h1")
(r_h2, h2_r) = connect(r, out_h2, "r-h2", "h2-r")

h1_r.set_address("64:ff9b::2/96")
r_h1.set_address("64:ff9b::1/96")

with r:
    exec_subprocess(f"ip addr add 10.0.1.253 dev {r_h1.id}")

r_h2.set_address("11.0.1.1/24")
h2_r.set_address("11.0.1.2/24")

# # r.add_route("11.0.1.0/24", r_h2)
# with r:
#     exec_subprocess("ip route add 11.0.1.0/24 dev r-h2 via 11.0.")
out_h2.add_route("DEFAULT", h2_r)
int_h1.add_route("DEFAULT", h1_r)


print("Running make")
print(os.system("sudo make"))
print(r_h1.name)
print("######## Make complete #####")

with r:
    os.system(f"sudo ./nat64 -i {r_h1.name} -4 10.0.1.0/24 -a 64:ff9b::/8")

print("nat64 running")

# print("starting nc listen")
# cmd = f"ip netns exec {r.id} nc -lnvp 3000"
# nc_listen_proc = Process(target=exec_subprocess, args=(cmd,))

print("starting wireshark")
cmd = f"ip netns exec {r.id} wireshark"
wireshark_proc = Process(target=exec_subprocess, args=(cmd,))
wireshark_proc.start()

cmd2 = f"ip netns exec {out_h2.id} wireshark"
wireshark_proc1 = Process(target=exec_subprocess, args=(cmd2,))
# wireshark_proc1.start()

time.sleep(20)

# print("sending nc")
# with int_h1:
#     os.system("nc -6 -v 64:ff9b:0000:0000:0000:0000:0000:a012 3000")

time.sleep(3000)
