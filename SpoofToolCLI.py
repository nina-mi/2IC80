import cmd
import os
import argparse
import threading

from arp_spoofing import *
from dns_spoofing import *

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
        parser.add_argument('-m', '--manual', nargs='*', help='Manual input of IP addresses')
        parser.add_argument('-r', '--router', help='Gateway router')
        parser.add_argument('-i', '--iface', default='enp0s10', help='Network Interface (default: enp0s10)')
        parser.add_argument('-a', '--auto', action='store_true', help='Automated IP adresses')
        
        try:
            args = parser.parse_args(line.split())
        except SystemExit:
            return  # argparse tries to exit the application when it fails
        
        # Pass parsed arguments to the arp_main function or handle them here
        if args.silent:
            print("Silent mode enabled.")
        if args.manual:
            print("Manual IP addresses: {}.".format(', '.join(args.manual)))
        if args.router:
            print("Gateway router: {}.".format(args.router))
        if args.iface:
            print("Network interface: {}".format(args.iface))
        if args.auto:
            arp_thread = threading.Thread(target=arp_main_automated) #todo integrate with iface and silent args
            arp_thread.start()

        # Call the arp_main function with the parsed arguments

        
        
        # Create a new thread that will run the arp_main function
        arp_thread = threading.Thread(target=arp_main, args=(args.silent, args.manual, args.router, args.iface))
        
        # Start the new thread
        arp_thread.start()

    def do_dns_spoof(self, line):
        """Spoof DNS packets."""
        parser = argparse.ArgumentParser(prog='dns_spoof', description='Spoof DNS packets.')
        print("dns spoofing started")
        # idk what arguments we might want
        dns_main()
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
        arp_spoofing.arp_spoofing = False
        dns_spoofing.dns_spoofing = False
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


if __name__ == '__main__':
    SpoofToolCLI().cmdloop()