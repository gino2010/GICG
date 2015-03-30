#!/usr/bin/python
# -*- coding: utf-8 -*-
# Scan Google IPs
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
    return ip_range


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
def scan_ip_range(ranges):
    output = open('raw_output', 'w')
    lock = multiprocessing.Lock()
    processes = []
    for item in ranges:
        processes.append(ScanProcess(item, output, lock))

    runtemp = []
    for i in xrange(4):
        item = processes.pop()
        item.start()
        runtemp.append(item)

    runflag = True
    while runflag:
        for item in runtemp:
            item.join(1)
            if not item.is_alive() and processes:
                runtemp.remove(item)
                item = processes.pop()
                item.start()
                runtemp.append(item)
            elif not processes:
                runflag = False
            break

    for item in runtemp:
        item.join()

    output.close()


if __name__ == '__main__':
    ip_range = get_google_ip_range()
    scan_ip_range(ip_range)