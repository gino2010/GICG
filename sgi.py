#!/usr/bin/python
# -*- coding: utf-8 -*-
# Scan Google IP
# https://gist.github.com/mashihua/96d8cc11bfedb9098f85
import multiprocessing

import os
import re
import subprocess

__author__ = 'gino'


# Get Google ip range
def get_google_ip_range():
    cmd = os.popen('nslookup -q=TXT _netblocks.google.com 8.8.8.8')
    output = cmd.read()
    pattern = re.compile(r'ip4:(.*?) ')
    ip_range = pattern.findall(output)
    # Beijing: 203.208.32.0 - 203.208.63.255
    ip_range.append('203.208.32.0/19')
    return ip_range


# nmap process scan port 433
class ScanProcess(multiprocessing.Process):
    def __init__(self, ip_add, file, lock):
        multiprocessing.Process.__init__(self)
        self.ip_add = ip_add
        self.file = file
        self.lock = lock

    def run(self):
        cmd = 'nmap -T5 -p443 --host-timeout 1000 ' + self.ip_add
        print(cmd)
        pipe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        result = pipe.communicate()[0]
        self.lock.acquire()
        print(cmd + ' write into file!')
        self.file.write(result)
        self.file.flush()
        self.lock.release()


# scan ip range
def scan_ip_range(ranges):
    output = open('raw_output', 'w')
    lock = multiprocessing.Lock()
    processes = []
    for item in ranges:
        processes.append(ScanProcess(item, output, lock))

    #each group 4 items to run
    while processes:
        i = 0
        temp = []
        for item in processes:
            if i == 4:
                break
            item.start()
            temp.append(item)
            i += 1
        for item in temp:
            item.join()
            processes.remove(item)

    # for item in ranges:
    #     cmd = 'nmap -p443 ' + item
    #     print(cmd)
    #     pipe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    #     result = pipe.communicate()[0]
    #     output.write(result)

    output.flush()
    output.close()


if __name__ == '__main__':
    ip_range = get_google_ip_range()
    scan_ip_range(ip_range)