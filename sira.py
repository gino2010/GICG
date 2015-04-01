#!/usr/bin/python
# -*- coding: utf-8 -*-
# Sort IP and Reverse to Address
import argparse
import re
import operator

import requests


__author__ = 'gino'


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
            # latency less than 1S
            latency = re.findall(r'0.\d+', lines[num - 2])
            if latency:
                try:
                    match_ips[re.findall(r'[0-9]+(?:\.[0-9]+){3}', lines[num - 3])[0]] = float(latency[0])
                except:
                    print('line %s error!' % num)

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
                    list_temp.remove(str_temp)

            print('{} is checked'.format(add_ip))
        except requests.exceptions.ConnectTimeout:
            fot.write(add_ip + ' is timeout \n')
            print('{} is timeout'.format(add_ip))
        except Exception as e:
            fot.write(add_ip + ' is error \n')
            print('{} is error, message:{}'.format(add_ip, e.message))

        rest_num -= 1
        if rest_num > 0:
            print('left {} item(s) will be check.'.format(str(rest_num)))
        else:
            print('left {} address(s) need to check.'.format(len(list_temp)))
            if len(list_temp) != outcount:
                print(list_temp)
                outcount = len(list_temp)

        if not list_temp or not rest_num:
            break

    if list_temp:
        print('Notice: %s not found ip' % str(list_temp))
    else:
        print('Total {} items have been checked'.format(0 - rest_num if rest_num < 0 else rest_num))
    fot.close()

    #output distinct address
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