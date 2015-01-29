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
First, you should run sgi.py to find potential available google ips, and get raw_output file for nex step.

    Python sgi.py
Notice: run sgi.py, it will take a few minutes, maybe one or more hours, please waiting...

License
-------
MIT


[Dnsmasq]:  http://www.thekelleys.org.uk/dnsmasq/doc.html
[Python]:   https://www.python.org/
[Nmap]:     http://nmap.org/
