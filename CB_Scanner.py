import nmap
import socket
import re
from mcstatus import JavaServer
from colorama import Fore, init
from tqdm import tqdm
import sys
import os

init()

def get_valid_input(prompt, options):
    while True:
        try:
            print(prompt)
            for key, value in options.items():
                print(f"{key}. {value}")
            user_input = input("> ")
            if user_input in options:
                return user_input
            else:
                print(Fore.RED + '[!] Invalid selection. Please select a valid option. [!]')
                print('')
        except KeyboardInterrupt:
            print(Fore.RED + '[!] Pressing Ctrl + C will exit the program.\n' + Fore.RED + 'Do you want to continue? (Y/N): ' + Fore.RESET, end='')
            confirmation = input().strip().lower()
            if confirmation == 'y':
                continue
            elif confirmation == 'n':
                print(Fore.RED + '[!] Exiting the program...' + Fore.RESET)
                sys.exit(1)
            else:
                print(Fore.RED + '[!] Invalid input. Please enter "Y" or "N".' + Fore.RESET)

def strip_color(text):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def save_to_file(output):
    save = input(Fore.LIGHTBLACK_EX + '[?] Do you want to save the output to a text file? (y/n): ' + Fore.RESET)
    if save.lower() == 'y':
        filename = input(Fore.LIGHTBLACK_EX + '[?] Enter the filename (or press Enter for default "Saved_Scan.txt"): ' + Fore.RESET)
        print('')
        if not filename:
            filename = "Saved_scan.txt"
        try:
            with open(filename, 'w') as file:
                file.write(strip_color(output))
            print(Fore.GREEN + '[+] Output saved successfully.' + Fore.RESET)
            print('')
        except Exception as e:
            print(Fore.RED + f"[!] An error occurred while saving the file: {e}" + Fore.RESET)

def main():
    os.system('cls')
    print(Fore.RED + r"   _____          _        ____                 _                 ")
    print(r"  / ____|        | |      |  _ \               | |                ")
    print(r" | |     ___   __| | ___  | |_) |_ __ ___  __ _| | _____ _ __ ___ ")
    print(r" | |    / _ \ / _` |/ _ \ |  _ <| '__/ _ \/ _` | |/ / _ | '__/ __|")
    print(r" | |___| (_) | (_| |  __/ | |_) | | |  __| (_| |   |  __| |  \__ \ ")
    print(r"  \_____\___/ \__,_|\___| |____/|_|  \___|\__,_|_|\_\___|_|  |___/")
    print("                                                                  ")
    print(Fore.LIGHTRED_EX + r"             _____                                                ")
    print(r"            / ____|                                               ")
    print(r"            | (___   ___ __ _ _ __  _ __   ___ _ __               ")
    print(r"             \___ \ / __/ _` | '_ \| '_ \ / _ | '__|              ")
    print(r"             ____) | (_| (_| | | | | | | |  __| |                 ")
    print(r"            |_____/ \___\__,_|_| |_|_| |_|\___|_|                 ")
    print("                                                                  ")
    print(Fore.RESET)

    print('               Welcome to '+ Fore.RED + 'CodeBreakers ' + Fore.RESET + 'Scanner')
    print('        Made by: '+ Fore.LIGHTRED_EX +'CB Team ' + Fore.RESET +' | Discord: ' + Fore.LIGHTRED_EX + 'discord.gg/8PtwWXnT5w' + Fore.RESET)
    print('')

    try:
        ip = socket.gethostbyname(input(Fore.LIGHTBLACK_EX + '[' + Fore.RED + 'CB' + Fore.LIGHTRED_EX +' Scanner' + Fore.LIGHTBLACK_EX + '] ' +  Fore.RESET + 'Enter the IP address you want to scan (mc.example.com): '))
        print('')
    except socket.gaierror as e:
        print(Fore.RED + f"[!] Error: {e}" + Fore.RESET)
        exit()

    scan_options = {
        '1': 'All ports scan',
        '2': 'AgarGriefing scan',
        '3': 'Specific ports scan'
    }
    scan_type = int(get_valid_input(Fore.LIGHTBLACK_EX + '[' + Fore.RED + 'CB' + Fore.LIGHTRED_EX +' Scanner' + Fore.LIGHTBLACK_EX + '] ' +  Fore.RESET + 'Select the type of scan you want to perform:', scan_options))
    print('')

    nm = nmap.PortScanner()

    try:
        if scan_type == 1:
            print(Fore.LIGHTBLACK_EX + '[' + Fore.RED + 'CB' + Fore.LIGHTRED_EX +' Scanner' + Fore.LIGHTBLACK_EX + '] ' +  Fore.LIGHTGREEN_EX + 'Scan started...wait for the result!')
            print('')
            nm.scan(ip, '1-65535')
        elif scan_type == 2:
            print(Fore.LIGHTBLACK_EX + '[' + Fore.RED + 'CB' + Fore.LIGHTRED_EX +' Scanner' + Fore.LIGHTBLACK_EX + '] ' +  Fore.LIGHTGREEN_EX + 'Scan started...wait for the result!')
            print('')
            nm.scan(ip, '10000-10010,20000-20010,30000-30010,40000-40010,22222,11111,33333,44444,55555,65535,25500-25599,25600-25699')
        elif scan_type == 3:
            ports = input(Fore.LIGHTBLACK_EX + '[' + Fore.RED + 'CB' + Fore.LIGHTRED_EX +' Scanner' + Fore.LIGHTBLACK_EX + '] ' +  Fore.RESET +  'Enter the ports you want to scan (comma separated): ')
            print('')
            print(Fore.LIGHTBLACK_EX + '[' + Fore.RED + 'CB' + Fore.LIGHTRED_EX +' Scanner' + Fore.LIGHTBLACK_EX + '] ' +  Fore.LIGHTGREEN_EX + 'Scan started...wait for the result!')
            print('')
            nm.scan(ip, ports)
    except Exception as e:
        print(Fore.RED + f"[!] An error occurred during the scan: {e}" + Fore.RESET)
        exit()

    found_open_ports = False
    output = ""
    with tqdm(total=len(nm.all_hosts())) as pbar:
        for host in nm.all_hosts():
            found_open_ports = False
            temp_output = ""
            temp_output += Fore.LIGHTRED_EX +'----------------'+ Fore.RED +'CodeBreakers Scanner'+ Fore.LIGHTRED_EX +'---------- ------'+ Fore.RESET + "\n"
            temp_output += f'Host : {host} ({nm[host].hostname()})\n\n'
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    if nm[host][proto][port]['state'] == 'open':
                        temp_output += Fore.RED + f'Port : ' + Fore.RESET + f'{port}\t' + Fore.RED +'State : '+ Fore.RESET + f'{nm[host][proto][ port]["state"]}\t'+ Fore.RED +'Protocol : '+ Fore.RESET + f'{proto}\n'
                        
                        server = JavaServer.lookup(host, port)
                        status = server.status()
                        temp_output += Fore.RED + 'Server : '+ Fore.RESET +f'{host}:{port}\n'
                        temp_output += Fore.RED + 'Version : ' + Fore.RESET + f'{status.version.name}\n'
                        temp_output += Fore.RED + 'Players : ' + Fore.RESET + f'{status.players.online}/{status.players.max}\n'
                        temp_output += '\n'
                        found_open_ports = True
            if found_open_ports:
                output += temp_output
            else:
                output += Fore.LIGHTBLACK_EX + '[' + Fore.RED + 'CB' + Fore.LIGHTRED_EX +' Scanner' + Fore.LIGHTBLACK_EX + '] ' + Fore.LIGHTRED_EX + 'No open ports found for host: ' + host + '\n '
            output += Fore.LIGHTRED_EX +'------------------------------------------ ----------'+ Fore.RESET + "\n"
            
            
            pbar.update(1)

    print(output)
    save_to_file(output)
    print(Fore.LIGHTBLACK_EX + '[' + Fore.RED + 'CB' + Fore.LIGHTRED_EX +' Scanner' + Fore.LIGHTBLACK_EX + '] ' +  Fore.LIGHTGREEN_EX + 'Scan completed')

    if sys.flags.interactive:
        print(Fore.GREEN + '[+] Resuming the program...' + Fore.RESET)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        if get_valid_input(Fore.RED + '\n[!] Pressing Ctrl + C will exit the program. Do you want to continue? (Y/N): ' + Fore.RESET).lower() == 'n':
            print(Fore.RED + '[!] Exiting the program...' + Fore.RESET)
            sys.exit(1)
        else:
            print(Fore.GREEN + '[+] Resuming the program...' + Fore.RESET)
            os.system('cls')
            main()
