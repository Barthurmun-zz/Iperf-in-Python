#!/usr/bin/env python3

'''
---------------------------------------------------------------------------------------------------------
AUTHOR: Jakub Bryl
TOPIC: Implementation of IPERF server which is working in daemon mode.

To make it work as daemon properly (we need to have some kind of informations back(some prints)
but in daemon mode we are detached from console thats why we need to enable syslogs !!!!)
I had to modify file: /etc/rsyslog.d/50-default.conf with this lines:

###################################################
!iperf_daemon
local7.*						/var/log/iperf.log
!*
###################################################


Support or TCP / UDP (which one to use should be included as an argument passed to script)

example of use:
./daemoniperf -T -n -i ::1 -6

If we chose '-m' it will force our server to listen on multicast address (client with same option
enabled will send datagram on multicast address), and after initiation of connection rest of transmition
will take place directly between client and server.

PYTHON 3 !
--------------------------------------------------------------------------------------------------------
'''

import socket
import sys
import os
import struct
import time
import argparse
import re
import syslog
import signal
import atexit

def ServerUDP(PORT, MCASTPORT, MCASTGRP, SNDB,BSIZE,TTL,HOST = 0, MULTI = False, IPV6 = False):
    ###############################################################################
    if IPV6 == False:

        regexmlt = re.search(
            '^((22[4-9]|23[0-9]).([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]).([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]).([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]))$',
            MCASTGRP)
        regex = re.search(
            '^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]).([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]).([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]).([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]))$',
            HOST)

        if regexmlt == None:
            syslog.syslog(syslog.LOG_ERR, ' IP address for multicast is invalid ! please try again with address from range: 224.0.0.0 - 239.255.255.255 \n')
            syslog.closelog()
            sys.exit()

        if regex == None:
            syslog.syslog(syslog.LOG_ERR,' IP address is invalid ! please try again with address from range: 0.0.0.0 - 255.255.255.255 \n')
            syslog.closelog()
            sys.exit()

        serv = HOST   #IP address which server expect the connection will come from
        mcast_grp = MCASTGRP

    else:
        serv = '::1'   #IP address which server expect the connection will come from
        mcast_grp = 'ff15:7079:7468:6f6e:6465:6d6f:6d63:6173'

    port = PORT  # port = PORT  # Arbitrary non-privileged port
    sndbuff = SNDB  # Size of Socket RCVBUFFOR
    buffsize = BSIZE  # size of data in udp datagram
    ttl = TTL
    mlt = MULTI
    mcast_port = MCASTPORT

    try:
        if IPV6 == False:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        else:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except socket.error as serror:
        syslog.syslog(syslog.LOG_ERR,'Unable to create a socket ! Error: ', serror)
    except Exception as msg:
        syslog.syslog(syslog.LOG_ERR,'Error not related to socket occured ! Error: ', msg)

    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, sndbuff)
        if IPV6 == False:
            s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    except socket.error as setsckerror:
        syslog.syslog(syslog.LOG_ERR,'Unable to set socket options ! Error: ', setsckerror , '\n')
    except Exception as msg:
        syslog.syslog(syslog.LOG_ERR,'Error not related to socket occured ! Error: ', msg)

    if mlt == True:  #AVOID NESTING TRY'S !
        try:
            if IPV6 == False:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
                #s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)  #If we will decide that we want to get back what we are sending
            else:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)
        except socket.error as multierror:
            syslog.syslog(syslog.LOG_ERR,'Unable to set socket options for multicast ! Error: ', multierror, '\n')

    syslog.syslog(syslog.LOG_NOTICE,'----------------------SERVER----------------------')
    syslog.syslog(syslog.LOG_NOTICE,'Socket created \n')
    syslog.syslog(syslog.LOG_NOTICE,'Server SNDBuff' + str(s.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)))
    syslog.syslog(syslog.LOG_NOTICE,'Server RCVBuff' + str(s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)))


    try:
        if IPV6 == False:
            if serv != '0.0.0.0' and mlt == False:
                s.bind((host, port))
            elif serv == '0.0.0.0' and mlt == True:
                s.bind(('',mcast_port))
            elif serv != '0.0.0.0' and mlt == True:
                s.bind((mcast_grp,mcast_port))
            elif mlt == False and serv == '0.0.0.0':
                s.bind(('', port))
        else:
            if serv != '::1' and mlt == False:
                s.bind((host, port))
            elif serv == '::1' and mlt == True:
                s.bind(('', mcast_port))
            elif serv != '::1' and mlt == True:
                s.bind((mcast_grp, mcast_port))
            elif mlt == False and serv == '::1':
                s.bind(('', port))


    except socket.error as msg:
        syslog.syslog(syslog.LOG_ERR,'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        syslog.closelog()
        sys.exit()
    except Exception as msg:
        syslog.syslog(syslog.LOG_ERR,'Error not related to socket occured ! Error: ', msg)
        sys.exit()

    syslog.syslog(syslog.LOG_NOTICE,'Socket binding complete succesfully')

    if mlt == True:
        try:
            if IPV6 == False:
                stru = struct.pack("4sl", socket.inet_aton(mcast_grp),socket.INADDR_ANY)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, stru)
            else:
                stru = socket.inet_pton(socket.AF_INET6, mcast_grp)
                mreq = stru + struct.pack('=I', socket.INADDR_ANY)
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
                
        except socket.error as errno:
            syslog.syslog(syslog.LOG_ERR,'Multicast options cannot be added ! Error: ', errno , '\n')
        except Exception as msg:
            syslog.syslog(syslog.LOG_ERR,'Error not connected to multicast occured ! Error : ', msg , '\n')

    while 1:
        syslog.syslog(syslog.LOG_NOTICE,'\n Waiting for connection request !')
        try:
            time_delivered = False

            while time_delivered == False:
                rcv, cliaddr = s.recvfrom(10)
                foo = int(rcv.decode())
                ack = 'ack'.encode()
                s.sendto(ack,cliaddr)
                if rcv != None:
                    time_delivered = True

        except socket.error as msg:
            if socket.errno.EINTR in msg.args:
                syslog.syslog(syslog.LOG_ERR,'A signal was interrupted before any data was available')
                continue
            elif socket.errno.EFAULT in msg.args:
                syslog.syslog(syslog.LOG_ERR,'Datagram that is sended is to big, cannot receive it ! ')
                break
            else:
                syslog.syslog(syslog.LOG_ERR,'Error occured ! Error : ', msg)
        except Exception as msg:
            syslog.syslog(syslog.LOG_ERR,'Error not related to socket occured ! Error: ', msg)

        data = ('z' * buffsize).encode()

        syslog.syslog(syslog.LOG_NOTICE,'user with address:  ' + str(cliaddr[0]) + ' asked for packets ')
        syslog.syslog(syslog.LOG_NOTICE,'user connected on port: ' + str(cliaddr[1]) +'\n')

        i = 0
        start_time = time.time()
        while 1:
            try:
                i += 1
                s.sendto(data,cliaddr)
                if (time.time() - start_time) > foo:
                    s.sendto('Last datagram'.encode(), cliaddr)
                    syslog.syslog(syslog.LOG_ERR,'Sended %d segments \n' % i)
                    break

            except socket.error as e:
                if socket.errno.ECONNRESET in e.args:
                    syslog.syslog(syslog.LOG_ERR,'Connection reseted by host side:', e)
                    break
                else:
                    syslog.syslog(syslog.LOG_ERR,'Error occured ! Error:', e)
            except Exception as msg:
                syslog.syslog(syslog.LOG_ERR,'Error not related to socket occured ! Error: ', msg)

    syslog.closelog()
    s.close()


def ServerTCP(PORT, SNDB, BSIZE, ALG_NAGLE=True, HOST=0, IPV6=False):
    host = HOST  # IP address which server expect the connection will come from
    port = PORT  # PORT nr. on which server will be open for clients
    sndbuff = SNDB  # size of socket SEND buffor
    buffsize = BSIZE  # size od data in tcp segment

    try:
        if IPV6 == False:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        else:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    except socket.error as serror:
        syslog.syslog(syslog.LOG_ERR, 'Unable to create a socket ! Error: ', serror)

    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, sndbuff)
        l_onoff = 1
        l_linger = 0
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
        if ALG_NAGLE == False:
            s.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        # s.setsockopt(socket.SOL_TCP,socket.TCP_MAXSEG,mss)
    except socket.error as setsckerror:
        syslog.syslog(syslog.LOG_ERR,'Unable to set socket options ! Error: ', setsckerror)

    syslog.syslog(syslog.LOG_NOTICE, '----------------------SERVER----------------------')
    syslog.syslog(syslog.LOG_NOTICE, 'Socket created \n')
    syslog.syslog(syslog.LOG_NOTICE, 'Server SNDBuff' + str(s.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)))
    syslog.syslog(syslog.LOG_NOTICE, 'Server RCVBuff' + str(s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)))

    try:
        if HOST != '0.0.0.0':
            s.bind((host, port))
        else:
            s.bind(('', port))
    except socket.error as msg:
        syslog.syslog(syslog.LOG_ERR, 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        syslog.closelog()
        sys.exit()

    syslog.syslog(syslog.LOG_NOTICE, 'Socket binding complete succesfully')

    s.listen(10)
    syslog.syslog(syslog.LOG_NOTICE, 'Socket is now listening \n')

    while 1:
        # wait to accept a connection - blocking call
        conn, addr = s.accept()

        rcv = conn.recv(10)
        foo = int(rcv.decode())
        data = ('z' * buffsize).encode()
        syslog.syslog(syslog.LOG_NOTICE, 'Connected with ' + addr[0] + ':' + str(addr[1]))

        i = 1
        start_time = time.time()
        while 1:
            try:
                i += 1
                conn.send(data)
                if (time.time() - start_time) > foo:
                    conn.close()
                    break

            except socket.error as msg:
                syslog.syslog(syslog.LOG_ERR, 'send error:', msg)
                break

    syslog.syslog(syslog.LOG_NOTICE, 'Sended %d segments \n' % i)
    syslog.closelog()
    s.close()


def Main():

    syslog.openlog("iperf_daemon", syslog.LOG_CONS | syslog.LOG_PID | syslog.LOG_NDELAY, syslog.LOG_LOCAL7) 
    syslog.setlogmask(syslog.LOG_UPTO(syslog.LOG_INFO))

    signal.signal(signal.SIGHUP, signal.SIG_IGN)


    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
        print('after first fork')
    except OSError as err:

        sys.stderr.write('First fork failed !'.format(err))
        sys.exit(1)

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
        print('after second fork')
    except OSError as err:
        sys.stderr.write('Second fork failed !'.format(err))
        sys.exit(1)

    try:
        os.chdir("/")
        os.setsid()
        os.umask(0)  # Any persmission may be set ( read, write, execute)

        sys.stdout.flush()  # write everything from stdout buffer on the terminal
        sys.stderr.flush()  # write everything from stderr buffer on the terminal
        si = open(os.devnull, 'r')
        so = open(os.devnull, 'a+')
        se = open(os.devnull, 'a+')

        os.dup2(si.fileno(), sys.stdin.fileno())  # Duplicates file descriptor si to sys.stdin.fileno(), we are using it bc
        os.dup2(so.fileno(), sys.stdout.fileno())  # other modules could acquired reference to it
        os.dup2(se.fileno(), sys.stderr.fileno())
    except Exception as msg:
        syslog.syslog(syslog.LOG_ERR,msg)

    pid = str(os.getpid())
    syslog.syslog(syslog.LOG_NOTICE, 'daemon started: ' + pid)

    parser = argparse.ArgumentParser(description='IPERF like script, IP address of socket on/to which you want to connect is REQUIRED, also option if you want to run SERVER or CLIENT')
    parser.add_argument('-i', '--ip', help = 'host/serv ip address, if you write ip address on server, server will expect connection only from this particular IP, if multicast is enabled and we '
                                             ' pass something here, server will bind with mcastgrp addr ! ' ,nargs = '?',type=str, default='0.0.0.0' )
    parser.add_argument('-p', '--port', help = 'Port number, default port nr. is 8888', type = int, default=8888,nargs = '?' )
    parser.add_argument('-l', '--len', help = 'Lenght of buffers to read and write, default = 128000',nargs = '?' , default= 128000, type=int)
    parser.add_argument('-bs','--buffsize', help = 'Option which controls amound of data that is transmitted every datagram, default = 8000',nargs = '?' , default= 8000, type = int)
    parser.add_argument('-t', '--time', help = 'ONLY SERVER option -> how much time measurment lasts, default = 10s', default=10, nargs = '?' ,type = int)
    parser.add_argument('-m', '--multicast', help='Turning on multicast ', action='store_true', default=False)
    parser.add_argument('-ttl', '--timetolive', help = 'Select the ttl for your packets, default = 20',nargs = '?' , default= 20, type=int)
    parser.add_argument('-mp', '--mcastport', help='Port number of multicast, default port nr. is 8000', type=int, default=8000, nargs='?')
    parser.add_argument('-mg', '--mcastgrp', help='IP addr of multicast , default ipv4 => 224.0.0.1 ipv6 => ff15:7079:7468:6f6e:6465:6d6f:6d63:6173', type=str, default='224.0.0.1', nargs='?')
    parser.add_argument('-6', '--IPV6', help='Use of IPV6, default one is IPv4 !', action='store_true', default=False)
    parser.add_argument('-T', '--TCP', help='If you want to use TCP ', action='store_true', default=False)
    parser.add_argument('-U', '--UDP', help='If you want to use UDP', action='store_true', default=False)
    parser.add_argument('-n', '--nagle', help='Turning off Nagle algorithm', action='store_false', default=True)

    args = parser.parse_args()

    if args.TCP and not args.UDP:
        ServerTCP(args.port, args.len, args.buffsize, args.nagle, args.ip, args.IPV6)
    elif args.UDP and not args.TCP:
        ServerUDP(args.port, args.mcastport, args.mcastgrp, args.len,args.buffsize, args.timetolive,args.ip, args.multicast, args.IPV6)
    elif args.TCP and args.UDP:
        print( 'You should chose either TCP or UDP ! ')
    else:
        print( 'Something went wrong ! ')

        
if __name__ == '__main__':
    Main()
