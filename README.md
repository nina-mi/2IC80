# 2IC80

This project also runs on Linux, but you need scapy installed. 
```
python -m pip install scapy
```

[npcap](https://npcap.com/#download) needs to be installed as well. 

For first-time usage, run setup.py to set up the environment with correct dependencies.

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