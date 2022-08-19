import os
import time
from multiprocessing import Process

import nest.config as config
from nest.engine.exec import exec_subprocess
from nest.topology import Node, Router, connect

config.set_value("assign_random_names", False)
# ipv4 Internal side
int_h1 = Node("h1")

r = Router("r")

# ipv4 side
out_h2 = Node("h2")


(h1_r, r_h1) = connect(int_h1, r, "h1-r", "r-h1")
(r_h2, h2_r) = connect(r, out_h2, "r-h2", "h2-r")

h1_r.set_address("10.0.1.2/24")
r_h1.set_address("10.0.1.1/24")


with r:
    os.system("ip route add 12.0.0.0/24 via 10.0.1.2")


r_h2.set_address("11.0.0.1/24")
h2_r.set_address("11.0.0.2/24")

out_h2.add_route("DEFAULT", h2_r)
int_h1.add_route("DEFAULT", h1_r)


print("Running make")
print(os.system("sudo make"))
print("######## Build complete #####")

with r:
    os.system(f"sudo ./nat64 -i {r_h1.id} -4 12.0.0.0/24 -a 64:ff9b::/8")

print("nat64 running")

print("starting wireshark")

cmd2 = f"ip netns exec {out_h2.id} wireshark"
wireshark_proc1 = Process(target=exec_subprocess, args=(cmd2,))
wireshark_proc1.start()

cmd2 = f"ip netns exec {int_h1.id} wireshark"
wireshark_proc2 = Process(target=exec_subprocess, args=(cmd2,))
wireshark_proc2.start()


time.sleep(3000)
