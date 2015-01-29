#!/usr/bin/python
# -*- coding: utf-8 -*-
# Sort IP and Reverse to Address
import argparse
import re
import operator

import requests


__author__ = 'gino'

list_add = []


def sort_all_ip():
    regex = re.compile("(.*)443/tcp open  https(.*)")
    match_lines = []
    match_ips = {}
    with open('raw_output', 'r') as fo:
        # search 443 is opened
        count = 0
        for line in fo:
            result = regex.search(line)
            if result is not None:
                match_lines.append(count)
            count += 1

        # get ips
        fo.seek(0)
        lines = fo.readlines()
        for num in match_lines:
            latency = re.findall(r'0.\d+', lines[num - 2])
            if latency is not []:
                try:
                    match_ips[re.findall(r'[0-9]+(?:\.[0-9]+){3}', lines[num - 3])[0]] = float(latency[0])
                except:
                    print('line %s wrong' % num)

    sorted_ips = sorted(match_ips.items(), key=operator.itemgetter(1))
    sif = open('sorted_list', 'w')

    for item in sorted_ips[:source_num]:
        sif.write(item[0] + ":" + str(item[1]) + "\n")
    sif.flush()
    sif.close()


def reverse_address(rest_num):
    fa = open('address_list', 'r')
    fot = open('timeout', 'w')
    output = []

    for line in fa:
        list_add.append(line.rstrip())

    set_add = set()

    sif = open('sorted_list', 'r')
    for line in sif:
        try:
            add_ip = line.split(':')[0]
            requests.get('https://{}'.format(add_ip), timeout=1)
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
            for str_temp in list_add:
                for item in rev_add_temp:
                    # if 'cache' in item: break
                    if str_temp in item and len(item.split('.')) <= 3:
                        output.append('address=/{}/{}\n'.format(str_temp, add_ip))
                        list_add.remove(str_temp)
                        break
            print('{} is checked'.format(add_ip))
        except requests.exceptions.ConnectTimeout:
            fot.write(add_ip + ' is timeout \n')
            print('{} is timeout'.format(add_ip))
        except:
            fot.write(add_ip + ' is error \n')
            print('{} is error'.format(add_ip))

        rest_num -= 1
        print('left {}'.format(str(rest_num)))

        if len(list_add) == 0:
            break

    fot.close()

    fca = open('collect_list', 'w')
    for item in set_add:
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
    sort_all_ip()
    print('Check top %d records and generate dnsmasq address list\n' % source_num)
    reverse_address(source_num)