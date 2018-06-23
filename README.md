# Iperf-in-Python
My implementation of Iperf in Python.
More explenation is added to the headers of this files
Iperf is divided into 2 files, each one works different. 

- iperf.py       Connects client&server into one file, everything depends on you how you will use it. 
                 Client example: ./iperf -c -i 127.0.0.1 -t 5 -m -bs 9000 
                 Client is responsible for defining amount of time for which measurement will take place
  
- daemoniperf.py Is just an Iperf server which is working as daemon process, all options supperted in iperf.py (in server mode) are also
                 supported here. Detailed information are provided in file header. 
