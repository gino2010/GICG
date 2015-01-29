Google IP address Configuration Generator
======
This project will help you to find available Google ip address, and Generate configuring content for [Dnsmasq].

You have to know about one thing that there are lots of available Google ips and you can enjoy Google service using them.
 This is reason why I write this project. 

This is pilot project now. So only test in specific environment.

Develop Environment
-------
* System: Mac OS X
* [Python] version: 2.7
* [Nmap] version: 6.47

Notice: You need to install Nmap software for running this project.

Usage
-------
First, you should run sgi.py to find potential available google ips, and get raw_output file for next step.

    Python sgi.py
Notice: 

* run sgi.py, it will take a few minutes, maybe one or more hours, please waiting...
* You should get raw_output file, this file is for next step


Second, run sira.py to generate dnsmasq address list

    python sira.py [max_num]
Notice: 

* You can modify address_list to set google domains which you want to search 
* max_num is number of records you want to check, default is 100.

Finally, you should get dnsmasq, collect_list, sorted_list, timeout, four output files.

* dnsmasq: address list
* collect_list: google domain, find from ip analysis, maybe you can find some you want to add to address_list
* sorted_list: process output, record these ips which you have searched
* timeout: record ips which timeout

License
-------
MIT


[Dnsmasq]:  http://www.thekelleys.org.uk/dnsmasq/doc.html
[Python]:   https://www.python.org/
[Nmap]:     http://nmap.org/
