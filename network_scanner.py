#!/usr/bin/env python


# MODULES IMPORTS
import subprocess
import scapy.all as scapy
import re


# Scan network and parse response
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(
        arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for item in answered_list:
        client_dict = {"ip": item[1].psrc, "mac": item[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


# Print the results found
def print_result(results_list):
    print("IP\t\t\tMAC Address\n")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])
        print("------------------------------------------")


# Find network router IP
def find_route():
    route = subprocess.check_output(["route", "-n"])
    route_string_raw = re.search(r"\d{3}\D\d+\D\d+\D\d+", str(route))
    result = ""
    if route_string_raw:
        result = route_string_raw.group(0)
    return result + "/24"


print_result(scan(find_route()))
