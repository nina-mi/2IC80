import cmd
import os
from arp_spoofing import *

class SpoofToolCLI(cmd.Cmd):
    prompt = 'SpoofTool>> '
    intro = '\nWelcome to SpoofToolCLI. Type "help" for available commands.'

    def __init__(self):
        super().__init__()
        self.current_directory = os.getcwd()

    # example of a command
    # def do_list(self, line):
    #     The text inside the triple quotes is the help text that will be displayed when the user types "help"
    #     """List files and directories in the current directory."""
    #     files_and_dirs = os.listdir(self.current_directory)
    #     for item in files_and_dirs:
    #         print(item)

    def do_arp_spoof(self, line):
        """Spoof ARP packets. Usage: arp_spoof [-s] [-m ip1 ip2 ip3 ...]"""
        # the [-s] means silent (ie not actively scanning for ip addresses)
        # the [-m ip1] means manual input of ip addresses
        arp_main(line)


    def do_clear(self, line):
        """Clear the screen."""
        os.system('clear')

    def do_dns_spoof(self, line):
        """Spoof DNS packets."""
        pass

    def do_quit(self, line):
        """Goodbye!"""
        return True

    def postcmd(self, stop, line):
        print()
        return stop

if __name__ == '__main__':
    SpoofToolCLI().cmdloop()