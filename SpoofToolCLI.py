import cmd
import os
import sys

import argparse
import threading
import atexit

import arp_spoofing
import dns_spoofing

import scapy.all as scapy

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
        parser.add_argument('-q', '--silent', action='store_true', help='Silent mode (no active scanning for IP addresses)')
        parser.add_argument('-m', '--manual', nargs='*', help='Manual input of IP addresses')
        parser.add_argument('-r', '--router', help='Gateway router')
        parser.add_argument('-i', '--iface', default='enp0s10', help='Network Interface (default: enp0s10)')
        parser.add_argument('-s', '--ssl', action='store_true', help='SSL stripping mode')
        
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

        attacker_addr = []
        try:
            attacker_addr.append(scapy.get_if_addr(args.iface))
            attacker_addr.append(scapy.get_if_hwaddr(args.iface))
        except TypeError:
            print("Attacker addresses not found, check interface")
            sys.exit()

        # Call the arp_main function with the parsed arguments
        #threading.Thread(target=arp_spoofing.arp_main, args=(attacker_addr, args.manual, args.router, args.iface, args.silent),
        #                     daemon=True).start()
        arp_spoofing.arp_main(attacker_addr, args.manual, args.router, args.iface, args.silent)
        # if args.ssl:
        #     print("SSL mode enabled")
        #     time.sleep(5) # wait for arp
        #     print("Starting SSL thread")
        #     threading.Thread(target=ssl_main, args=(attacker_addr, args.iface), daemon=True).start()

    def do_dns_spoof(self, line):
        """Spoof DNS packets."""
        parser = argparse.ArgumentParser(prog='dns_spoof', description='Spoof DNS packets.')
        print("dns spoofing started")
        # idk what arguments we might want
        dns_spoofing.dns_main()
        # dns_main(args)
        pass


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
        arp_spoofing = False
        dns_spoofing = False
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

if __name__ == '__main__':
    cli = SpoofToolCLI()
    
    def exit_handler():
        arp_spoofing.arp_looping = False
        dns_spoofing.dns_looping = False
        exit()
    atexit.register(exit_handler)

    cli.cmdloop()