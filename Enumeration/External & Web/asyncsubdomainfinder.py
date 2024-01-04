import requests
import argparse
import os
import sys
from dns.asyncresolver import Resolver
import dns.resolver
import dns.rrset
import asyncio
import socket
from pathlib import Path
import time

position = 0
wordlist_len = None


def getcrtshContent(url):
    r = requests.get("https://crt.sh/?q="+url )
    if r.status_code == 200:
        return r.content
    return None 

def filterContent(content, domain):
    unfiltered = str(content).split("<TD>")[1:]
    filtered = []
    for item in unfiltered:
        fqdn = item[:-11]
        if domain in item and "<BR>" not in item and fqdn not in filtered:
            filtered.append(fqdn)
    return filtered

def checkSubdomainValidity(subdomain, subdomainlist):
    try:
        ipaddress = socket.gethostbyname_ex(subdomain)[2]
    except:
        return False
    if len(ipaddress) and subdomain not in subdomainlist:
        return True
    return False


async def async_checkSubdomainValidity(ResolverObject, subdomain, isBruteforce):
    global position
    global wordlist_len
    try:
        res: dns.resolver.Answer = await ResolverObject.resolve(subdomain, rdtype='A', lifetime=1)
    except dns.resolver.NXDOMAIN:
        #if isBruteforce:
            #position += 1
            #print("\r", end="")
            #print("Bruteforcing subdomains: " + str(position/wordlist_len * 100) + "%. Current position: " + str(position) , end="")
        return False
    except KeyboardInterrupt:
        print("Exiting")
        asyncio.gather(*asyncio.Task.all_tasks()).cancel()
        sys.exit()
    #if isBruteforce:
        #position += 1
        #print("\r", end="")
        #print("Bruteforcing subdomains: " + str(position/wordlist_len * 100) + "%. Current position: " + str(position), end="")
    return subdomain


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", dest="domain",required=True)
    parser.add_argument("-w", "--wordlist", dest="wordlist", required=True)
    args = parser.parse_args()

    finalsubdomainlist = []
    rs = Resolver()
    
    # Gathering subdomains by DNS lookup brute force
    wordlistfilepath = Path(args.wordlist)
    if wordlistfilepath.is_file():
        with open(args.wordlist, 'r', encoding="ISO-8859-1") as wordlistfile:
            wordlist = wordlistfile.readlines()

    global wordlist_len
    wordlist_len = len(wordlist)
    global position
    """
    coros1 = [async_checkSubdomainValidity(rs, currentword[:-1] + "." + args.domain, True) for currentword in wordlist]
    res = await asyncio.gather(*coros1, return_exceptions=True)
    for currentsubdomain in res:
        if currentsubdomain and currentsubdomain not in finalsubdomainlist:
            finalsubdomainlist.append(currentsubdomain)
    """
    while position < wordlist_len: # CHECK condition
        if position + 200 < wordlist_len: # Check condition
            coros1 = [async_checkSubdomainValidity(rs, currentword[:-1] + "." + args.domain, True) for currentword in wordlist[position:position + 200]]
        else:
            coros1 = [async_checkSubdomainValidity(rs, currentword[:-1] + "." + args.domain, True) for currentword in wordlist[position:wordlist_len]]
        res = await asyncio.gather(*coros1, return_exceptions=True)
        for currentsubdomain in res:
            if currentsubdomain and currentsubdomain not in finalsubdomainlist:
                finalsubdomainlist.append(currentsubdomain)
        position += 200
        print("\r", end="")
        print("Bruteforcing subdomains: " + str(position/wordlist_len * 100) + "%. Current position: " + str(position), end="")
        time.sleep(2)
    

    # Gathering subdomains from certificates on crt.sh
    responseBody = getcrtshContent(args.domain)
    subdomainlistunfiltered = filterContent(responseBody,str(args.domain))
    coros2 = [async_checkSubdomainValidity(rs, subdomain, False) for subdomain in subdomainlistunfiltered]
    res = await asyncio.gather(*coros2, return_exceptions=True)
    for currentsubdomain in res:
        if currentsubdomain and currentsubdomain not in finalsubdomainlist:
            finalsubdomainlist.append(currentsubdomain)
    
    
    print("\n")
    for item in finalsubdomainlist:
        print(item)


if __name__ == "__main__":
    asyncio.run(main())
