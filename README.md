# 2IC80


## Setup
This project also runs on Linux, but you need scapy installed. 
```
python -m pip install scapy
```

[npcap](https://npcap.com/#download) needs to be installed as well. 

For first-time usage, run the setup commands below in a Linux terminal to set up the environment with correct dependencies.
```
sudo pip install pip==18.0
sudo pip install --upgrade pip
sudo apt-get install build-essential python-dev libnetfilter-queue-dev
sudo pip install NetfilterQueue
sudo apt-get install python-twisted-web
sudo echo "1" > /proc/sys/net/ipv4/ip_forward
```


To start interacting with the SpoofToolCLI, you need to run this in terminal:

```
sudo python SpoofToolCLI.py
```




## Available Commands

To see all commands, type ```help``` once the CLI is running.

Typing ```<command> -h``` shows the usage of the command.

### `arp_spoof`
Spoof ARP packets to intercept traffic in the network.

#### Usage
```shell
arp_spoof [-h] [-s] [-m [MANUAL [MANUAL ...]]] [-r ROUTER] [-i IFACE]
```

#### Options
-h, --help:
Show help message and exit.

-q, --silent:
Silent mode (no active scanning for IP addresses).

-m [MANUAL [MANUAL ...]], --manual [MANUAL [MANUAL ...]]:
Manual input of IP addresses (default is entire subnet). Also requires --router.

-r ROUTER, --router ROUTER:
Gateway router.

-i IFACE, --iface IFACE:
Network Interface (default: enp0s10).

---

### `dns_spoof`

#### Usage
```shell
dns_spoof [-h] [-m [MANUAL [MANUAL ...]]] [-i IFACE]
```

#### Options
-h, --help:
Show help message and exit.

-m [MANUAL [MANUAL ...]], --manual [MANUAL [MANUAL ...]]:
Manual input of URLs (default: all).

-i IFACE, --iface IFACE:
Network Interface (default: enp0s10).

---

### `clear`

Clear the screen.

---

### `quit`

Quit the program.

---

### `exit`

Exit the program