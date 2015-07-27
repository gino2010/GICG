#!/usr/bin/python
# -*- coding: utf-8 -*-
# Sort IP and Reverse to Address
import argparse
import re
import operator
import requests
from requests.packages import urllib3

urllib3.disable_warnings()

__author__ = 'gino'

IGNORE_IP = ['216.', ]
ONLY_IP = []


def filter_ip(ip):
    if ONLY_IP:
        for item in ONLY_IP:
            if ip.startswith(item):
                return False
        return True
    else:
        for item in IGNORE_IP:
            if ip.startswith(item):
                return True
        return False


def sort_all_ip():
    regex = re.compile("443/tcp open  https|443/tcp filtered https")
    match_lines = []
    match_ips = {}
    with open('raw_output', 'r') as fo:
        # search 443 is opened
        count = 0
        for line in fo:
            result = regex.search(line)
            if result is not None and result.string == '443/tcp open  https\n':
                match_lines.append((count, 0))
            elif result is not None and result.string == '443/tcp filtered https\n':
                match_lines.append((count, 1))
            count += 1

        # get ips
        fo.seek(0)
        lines = fo.readlines()
        for item in match_lines:
            latency = 1.0
            if item[1] == 0:
                # latency less than 1S
                temp = re.findall(r'0.\d+', lines[item[0] - 2])
                if temp:
                    latency = temp[0]
                else:
                    continue
            elif item[1] == 1:
                temp = re.findall(r'Host is up\.', lines[item[0] - 2])
                if not temp:
                    continue
            try:
                ip_addresses = re.findall(r'[0-9]+(?:\.[0-9]+){3}', lines[item[0] - 3])
                ip_address = ip_addresses[1] if len(ip_addresses) == 2 else ip_addresses[0]
                if filter_ip(ip_address):
                    print('pass %s address' % ip_address)
                    continue
                match_ips[ip_address] = float(latency)
            except:
                print('line %s error!' % item[0])

    return sorted(match_ips.items(), key=operator.itemgetter(1))


# get address map ip
def reverse_address(rest_num, sorted_ips):
    fot = open('timeout', 'w')
    fca = open('collect_list', 'w')
    output = []
    list_add = []

    with open('address_list', 'r') as fa:
        for line in fa:
            list_add.append(line.rstrip())
    list_temp = list_add[:]

    set_add = set()
    outcount = 0

    try:
        for item in sorted_ips:
            try:
                add_ip = item[0]
                requests.get('https://{}'.format(add_ip), timeout=1.5)
            except requests.exceptions.SSLError as e:
                message = str(e.message)
                pos = message.find('of')
                rev_add_temp = []
                if pos != -1:
                    rev_add_temp = message[message.find('of') + 4:-1].split("', '")
                else:
                    rev_add_temp.append(message[message.find('match') + 7:-1])
                # just collect site address
                set_add = set_add.union(set(rev_add_temp))
                fca.write('ip:{} address:{} \n'.format(add_ip, str(rev_add_temp)))
                list_add = list_temp[:]
                for str_temp in list_add:
                    if str_temp in rev_add_temp:
                        output.append(
                            'address=/{}/{}\n'.format(str_temp[2:] if str_temp.startswith('*.') else str_temp, add_ip))
                        # add a rule for ingress
                        if str_temp == '*.google.com':
                            output.append('address=/{}/{}\n'.format('m-dot-betaspike.appspot.com', add_ip))
                        list_temp.remove(str_temp)

                print('{} is checked'.format(add_ip))
            except requests.exceptions.ConnectTimeout:
                fot.write(add_ip + ' is TIMEOUT \n')
                print('{} is timeout'.format(add_ip))
            except Exception as e:
                fot.write(add_ip + ' is ERROR \n')
                print('{} is error, message:{}'.format(add_ip, e.message))

            rest_num -= 1
            if rest_num > 0:
                print('left {} item(s) will be check.'.format(str(rest_num)))
            else:
                print('left {} address(es) need to check and already check {} address(es).'.format(len(list_temp),
                                                                                                   0 - rest_num))
                if len(list_temp) != outcount:
                    print(list_temp)
                    outcount = len(list_temp)

            if not list_temp or not rest_num:
                break
    except KeyboardInterrupt:
        print('abort scan...')

    if list_temp:
        print('Notice: %s not found ip' % str(list_temp))
        for temp in list_temp:
            output.append('address=/{}/{}\n'.format(temp[2:] if str_temp.startswith('*.') else str_temp, '0.0.0.0'))
    else:
        print('Total {} items have been checked'.format(0 - rest_num if rest_num < 0 else rest_num))
    fot.close()

    # output distinct address
    collect_list = list(set_add)
    collect_list.sort()
    for item in collect_list:
        fca.write(item + '\n')
    fca.flush()
    fca.close()

    ffd = open('dnsmasq', 'w')
    output.sort()
    for line in output:
        ffd.write(line)
    ffd.flush()
    ffd.close()


def parse_args():
    parser = argparse.ArgumentParser(description='Scan and reverse address.')
    parser.add_argument('integers', metavar='Num', type=int, nargs='?',
                        help='an integer for the number of scan', default=100)
    return parser.parse_args().integers


if __name__ == '__main__':
    source_num = parse_args()
    print('Start to analyse file and sort ip records by latency\n')
    sorted_ips = sort_all_ip()
    print('Check top %d records and generate dnsmasq address list\n' % source_num)
    reverse_address(source_num, sorted_ips)
