#!/usr/bin/python
# -*- coding: utf-8 -*-
# Scan Google IPs
import argparse
import multiprocessing

import os
import re
import subprocess

__author__ = 'gino'

IGNORE_IP = ['216.239.32.0/19', '216.58.192.0/19']
EXTRA_IP = ['87.245.192.0/18', ]


# Get Google ip range
def get_google_ip_range():
    cmd = os.popen('nslookup -q=TXT _netblocks.google.com 8.8.8.8')
    output = cmd.read()
    pattern = re.compile(r'ip4:(.*?) ')
    ip_list = pattern.findall(output)
    for item in IGNORE_IP:
        ip_list.remove(item)
    ip_list.extend(EXTRA_IP)
    return ip_list


# nmap process scan port 433
class ScanProcess(multiprocessing.Process):
    def __init__(self, ip_add, outfile, lock):
        multiprocessing.Process.__init__(self)
        self.ip_add = ip_add
        self.outfile = outfile
        self.lock = lock

    def run(self):
        cmd = 'nmap -T5 -p443 --host-timeout 1000 ' + self.ip_add
        print(cmd)
        pipe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        result = pipe.communicate()[0]
        self.lock.acquire()
        print(cmd + ' write into file!')
        self.outfile.write(result)
        self.outfile.flush()
        self.lock.release()


# scan ip range
def scan_ip_range(ranges, mnum):
    output = open('raw_output', 'w')
    lock = multiprocessing.Lock()
    processes = []
    for item in ranges:
        processes.append(ScanProcess(item, output, lock))
    print('%d items will be checked.' % len(processes))

    import datetime
    print('start: %s' % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # initial runtemp gourp
    runtemp = []
    for i in xrange(mnum):
        item = processes.pop()
        item.start()
        runtemp.append(item)

    while True:
        for i in xrange(len(runtemp)):
            runtemp[i].join(1)
            if not runtemp[i].is_alive() and processes:
                runtemp[i] = processes.pop()
                runtemp[i].start()
            elif not runtemp[i].is_alive() and not processes:
                runtemp.pop(i)
                break
        if not runtemp:
            break

    print('end: %s' % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    output.close()


def parse_args():
    parser = argparse.ArgumentParser(description='Number of multiprocess')
    parser.add_argument('integers', metavar='Num', type=int, nargs='?',
                        help='an integer for the number of multiprocess', default=4)
    return parser.parse_args().integers

if __name__ == '__main__':
    arg_num = parse_args()
    ip_range = get_google_ip_range()
    scan_ip_range(ip_range, arg_num)