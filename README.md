# NAT44 & NAT64 implementation using TC-BPF 

## Tested Environment
```
OS: Ubuntu 22.04
Kernel: 5.15.0-46-generic
Python: 3.10.4
iproute: iproute2-5.15.0
```


## Dependencies:
- nest
    ```bash
    pip3 install nest
    ```

- scapy, wireshark
    ```bash
    sudo apt install python3-scapy wireshark
    ```

- Toolchains/headers & helpers for eBPF
    ```bash
    sudo apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential libmnl-dev
    sudo apt install linux-tools-$(uname -r)
    sudo apt install linux-headers-$(uname -r)
    sudo apt install linux-tools-common linux-tools-generic
    ```

## Running:

- Change directory to nat44-bpf / nat64-bpf
- Create the topology & compile & start nat ebpf program

    ```
    sudo python3 testbed.py
    ```
    > The script will start wireshark instances in the end hosts & router nodes(h1, h2 & r).

    > This script has to be running in foreground. The below operations has to be done in a new shell

- Send a packet from h1 to h2
    ```
    sudo ip netns exec h1 python3 send_pkt.py
    ```

- Send a packet from h2 to h1
    ```
    sudo ip netns exec h2 python3 ret_pkt.py
    ```

- The packets can be analyzed using wireshark at hosts or router nodes.
