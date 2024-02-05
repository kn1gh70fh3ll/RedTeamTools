import json
import argparse
import socket


cidr_ranges = []

def parse_bloodhound_json(jsonfile):
    """
    Accepts a .json file exported from BloodHound's Domain Computers graph
    Saves the results containing the list of FQDNs in a file called all_hostnames.txt
    """
    with open(jsonfile, 'r') as datafile:
        data = json.load(datafile)

    with open('all_hostnames.txt','w') as fd:
        for i in range(len(data['nodes'])):
            fd.write(data['nodes'][i]['props']['name']+'\n')

def host_lookups():
    with open('all_hostnames.txt', 'r') as hostsfile:
        hostnames = hostsfile.readlines()

    for host in hostnames:
        try:
            host_ips = socket.gethostbyname_ex(host[:-1])[2]
            for ip in host_ips:
                subnet = ".".join(ip.split('.')[0:3])
                if subnet not in cidr_ranges:
                    cidr_ranges.append(subnet)
        except socket.gaierror:
            continue

def parse_filter(raw_filter_str):
    filter_ranges = []
    
    parsed_filter = raw_filter_str.split(',')
    for cidr in parsed_filter:
        filter_ranges.append('.'.join(cidr.split('.')[0:2]))

    return filter_ranges


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-j", "--jsonfile", dest="jsonfile",required=True, help=".json file exported from BloodHound of the Domain Computers graph.")
    parser.add_argument("-f", "--filter", dest="filter", required=False, help="/16 CIDR ranges separated by comma WITHOUT spaces. Eg. --filter 172.10.0.0/16,172.20.0.0/16")
    args = parser.parse_args()

    parse_bloodhound_json(args.jsonfile)
    host_lookups()
    print("Subnet ranges detected:")

    with open("cidr_ranges.txt",'w') as result_file:
        if args.filter:
            filtered_ranges = parse_filter(args.filter)
            for sub in cidr_ranges:
                if str(".".join(sub.split(".")[0:2])) not in filtered_ranges:
                    continue
                print(sub + ".0/24")
                result_file.write(sub + ".0/24"+'\n')
        else:
            for sub in cidr_ranges:
                print(sub + ".0/24")
                result_file.write(sub + ".0/24"+'\n')


if __name__ == "__main__":
    main()