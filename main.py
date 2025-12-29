from tabulate import tabulate
import pyfiglet

import sys
import pandas as pd

from library.shared.categorise import Categorise

def banner():
    print(pyfiglet.figlet_format("OSINTify Results"))
    print("""
Version: 1.0.0 | Release: 2025-12-28
Author: Tux Payne <coding.tux.payne@protonmail.ch>

OSINT automation tool for parsing and categorizing IOCs, checking them against some tools.

Disclaimer: OSINTify is provided "as is". Use at your own risk.
The author is not responsible for any misuse, damages, or legal consequences.
        
Type --help for usage instructions
""")

def results(Results, Name: str  ) -> None:
    if not Results.empty:
        print(pyfiglet.figlet_format(Name, font="small"))
        print(tabulate(Results, tablefmt="grid", headers=Results.columns.tolist()))


def osintify(input):
    IP_results = pd.DataFrame()
    HASH_results = pd.DataFrame()
    
    for line in input:
        ioc = Categorise(line)
        
        if ioc.type == "IP":
            IP_results.at[ioc.value,"Type"] = ioc.type
            IP_results.at[ioc.value,"Details"] = ioc.detail
            IP_results.at[ioc.value,"Shodan Known"] = str(ioc.shodan.is_known()) if ioc.shodan else "-"
            IP_results.at[ioc.value,"Open Ports"] = str(ioc.shodan.exposed_ports()) if ioc.shodan and (ioc.shodan.is_known()  and ioc.detail == "public") else "N/A" 
            IP_results.at[ioc.value,"VT ASN"] = ioc.virusTotal.asn() if ioc.detail == "public" else "N/A"
            IP_results.at[ioc.value,"VT ASN Owner"] = ioc.virusTotal.owner() if ioc.detail == "public" else "N/A"
            IP_results.at[ioc.value,"VT Country"] = ioc.virusTotal.country() if ioc.detail == "public" else "N/A"
            IP_results.at[ioc.value,"VT Score mal/sus/harmless"] = ioc.virusTotal.score() if ioc.detail == "public" else "N/A"

        if ioc.type == "HASH":
            HASH_results.at[ioc.value,"Type"] = ioc.type
            HASH_results.at[ioc.value,"Details"] = ioc.detail
            HASH_results.at[ioc.value,"VT Score mal/sus/harmless"] = ioc.virusTotal.score() if ioc.virusTotal.score() else "N/A"

    results(IP_results, "IP Results")
    results(HASH_results, "Hash Results")


if __name__ == '__main__':
    banner()
    osintify(sys.stdin)