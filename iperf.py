#!/usr/bin/env python

'''
---------------------------------------------------------------------------------------------
AUTHOR: Jakub Bryl
TOPIC: Implementation of IPERF with multicast support !

If we enable multicast by adding -m option to the script, server will bind to multicast addr
and listen for the requests, if client (client is sending "initialization packet" on multicast address
if we add '-m' to script with client mode ('-c')) ask for connection, server is responding 
directly to his address and measurement of throughput is stared.

PYTHON 3 !
----------------------------------------------------------------------------------------------
'''

import socket
import sys
import os
import struct
import time
import argparse
import re

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
            print(
                ' IP address for multicast is invalid ! please try again with address from range: 224.0.0.0 - 239.255.255.255 \n')
            sys.exit()

        if regex == None:
            print(' IP address is invalid ! please try again with address from range: 0.0.0.0 - 255.255.255.255 \n')
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
        print('Unable to create a socket ! Error: ', serror)
    except Exception as msg:
        print('Error not related to socket occured ! Error: ', msg)

    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, sndbuff)
        if IPV6 == False:
            s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    except socket.error as setsckerror:
        print('Unable to set socket options ! Error: ', setsckerror , '\n')
    except Exception as msg:
        print('Error not related to socket occured ! Error: ', msg)

    if mlt == True:  #AVOID NESTING TRY'S !
        try:
            if IPV6 == False:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
                #s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)  #If we will want to get back what we are sending
            else:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)
        except socket.error as multierror:
            print('Unable to set socket options for multicast ! Error: ', multierror, '\n')


    print('----------------------SERVER----------------------')
    print('Socket created \n')
    print('Server SNDBuff', s.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF))
    print('Server RCVBuff', s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),'\n')


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
        print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()
    except Exception as msg:
        print('Error not related to socket occured ! Error: ', msg)
        sys.exit()

    print('Socket binding complete succesfully')

    if mlt == True:
        try:
            if IPV6 == False:
                str = struct.pack("4sl", socket.inet_aton(mcast_grp),socket.INADDR_ANY)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, str)
            else:
                str = socket.inet_pton(socket.AF_INET6, mcast_grp)
                mreq = str + struct.pack('=I', socket.INADDR_ANY)
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
                
        except socket.error as errno:
            print('Multicast options cannot be added ! Error: ', errno , '\n')
        except Exception as msg:
            print('Error not connected to multicast occured ! Error : ', msg , '\n')

    while 1:
        print('\n Waiting for connection request !')
        try:
            time_delivered = False

            while time_delivered == False:
                rcv, cliaddr = s.recvfrom(10)
                foo = int(rcv.decode())
                ack = 'ack'.encode()
                s.sendto(ack, cliaddr)
                if rcv != None:
                    time_delivered = True

        except socket.error as msg:
            if socket.errno.EINTR in msg.args:
                print('A signal was interrupted before any data was available')
                continue
            elif socket.errno.EFAULT in msg.args:
                print('Datagram that is sended is to big, cannot receive it ! ')
                break
            else:
                print('Error occured ! Error : ', msg)
        except Exception as msg:
            print('Error not related to socket occured ! Error: ', msg)

        data = ('z' * buffsize).encode()

        print('user with address:  ', cliaddr[0] , ' asked for packets ')
        print('user connected on port: ', cliaddr[1],'\n')

        i = 0
        start_time = time.time()
        while 1:
            try:
                i += 1
                s.sendto(data,cliaddr)
                if (time.time() - start_time) > foo:
                    s.sendto('Last datagram'.encode(), cliaddr)
                    print('Sended %d segments \n' % i)
                    break

            except socket.error as e:
                if socket.errno.ECONNRESET in e.args:
                    print('Connection reseted by host side:', e)
                    break
                else:
                    print('Error occured ! Error:', e)
            except Exception as msg:
                print('Error not related to socket occured ! Error: ', msg)

    s.close()

def ClientUDP(HOST,PORT, MCASTPORT, MCASTGRP, RECVB,BSIZE, TTL, TIME, MULTI = False, IPV6 = False):

    ###############################################################################
    if IPV6 == False:

        regexmlt = re.search(
            '^((22[4-9]|23[0-9]).([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]).([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]).([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]))$',
            MCASTGRP)
        regex = re.search(
            '^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]).([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]).([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]).([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]))$',HOST)

        if regexmlt == None:
            print(
                ' IP address for multicast is invalid ! please try again with address from range: 224.0.0.0 - 239.255.255.255 \n')
            sys.exit()

        if regex == None:
            print(' IP address is invalid ! please try again with address from range: 0.0.0.0 - 255.255.255.255 \n')
            sys.exit()

        serv = HOST     # IP addr of server to which we want to connect
        mcast_grp = MCASTGRP

    else:
        serv = '::1' # IP addr of server to which we want to connect
        mcast_grp = 'ff15:7079:7468:6f6e:6465:6d6f:6d63:6173'

    port = PORT  # port = PORT  # Arbitrary non-privileged port
    rcvbuff = RECVB  # Size of Socket RCVBUFFOR
    buff = BSIZE  # size of data in udp datagram
    ttl = TTL
    mlt = MULTI
    mcast_port = MCASTPORT
    tim = TIME

    try:
        if IPV6 == False:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        else:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    except socket.error as serror:
        print('Unable to create a socket ! Error: ', serror)
    except Exception as msg:
        print('Error not related to socket occured ! Error: ', msg)

    print ('----------------------CLIENT----------------------')
    print('Socket created \n')


    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuff)
        s.settimeout(2)
    except socket.error as sckerror:
        print('Setting socket option failed ! Error: ', sckerror , '\n')
    except Exception as elol:
        print('Error not related to socket occured ! Error ', elol)

    if mlt == True:
        try:
            if IPV6 == False:
                s.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_TTL,ttl)
            else:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)
        except socket.error as errno:
            print('Error while setting multicast socket options ! Error: ', errno, '\n' )
        except Exception as msg:
            print('Error not connected with socket oocured ! Error : ', msg)

    print('Client RCVBuff:', s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))
    print('Client SNDBuff:', s.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF))

    ack_delivered = False
    while ack_delivered == False:
        intro = str(tim).encode()
        try:
            if mlt == False:
                s.sendto(intro,(serv,port))
            elif mlt == True:
                s.sendto(intro, (mcast_grp,mcast_port))

            ack, servaddr = s.recvfrom(10)
            ack = ack.decode()
            if ack == 'ack':
                ack_delivered = True

        except socket.error as elol:
            print('Unable to send initialization packet to server, Error :' , elol)
        except Exception as msg:
            print('Error not related to socket occured ! Error: ', msg)

    count = 0                   #Nr of datagrams received
    size = 0                    #Size od data received
    start_time = time.time()    #Countdown starts here !

    while 1:
        try:
            data, servaddr = s.recvfrom(buff)

        except socket.error as elol:
            if elol.args[0] in (socket.errno.EAGAIN, socket.errno.EWOULDBLOCK):
                print('Socket descriptor marked nonblocking and no data is waiting to be received')
                break
            elif s.timeout:
                print('2 seconds lasted from last datagram sended by the server ! ')
                break
            elif socket.errno.ECONNRESET in elol.args:
                print('Connection reseted by server side:', elol)
                break
            else:
                print('Unable to receive any data, Error:', elol )
                break
        except Exception as msg:
            print('Error not related to socket occured ! Error: ', msg)

        count = count + 1
        size += len(data)

    stop_time = time.time()
    duration = (stop_time - start_time) - 2
    trafic = ((size * 8.0) / 1000000) / duration
    print('Reading from socket in: (%f) s, : in (%d) segments (%d)((%f) mbit/s)\n' % (duration, count, size, trafic))
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
        print('Unable to create a socket ! Error: ', serror)

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
        print('Unable to set socket options ! Error: ', setsckerror, '\n')

    print('----------------------SERVER----------------------')
    print('Socket created \n')
    print('Server SNDBuff', s.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF))
    print('Server RCVBuff', s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF), '\n')

    try:
        if HOST != '0.0.0.0':
            s.bind((host, port))
        else:
            s.bind(('', port))
    except socket.error as msg:
        print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()

    print('Socket binding complete succesfully')

    s.listen(10)
    print('Socket is now listening \n')

    while 1:
        # wait to accept a connection - blocking call
        conn, addr = s.accept()

        rcv = conn.recv(10)
        foo = int(rcv.decode())
        data = ('z' * buffsize).encode()
        print('Connected with ' + addr[0] + ':' + str(addr[1]))

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
                print('send error:', msg)
                break

    print('Sended %d segments \n' % i)
    s.close()

def ClientTCP(HOST,PORT,RECVB,BSIZE,TIME, ALG_NAGLE = True, IPV6 = False):
    port = PORT     # port = PORT  # Arbitrary non-privileged port
    rcvbuff = RECVB #Size of Socket RCVBUFFOR
    buff = BSIZE    # size of data in tcp seg
    host = HOST     # IP addr of server to which we want to connect
    tim = TIME
    try:
        if IPV6 == False:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except socket.error as serror:
        print('Unable to create a socket ! Error: ', serror)


    print ('----------------------CLIENT----------------------')
    print('Socket created \n')

    # Bind socket to local host and port
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuff)
        if ALG_NAGLE == False:
            s.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        #s.setsockopt(socket.SOL_TCP,socket.TCP_MAXSEG,10000)  #Python not responding corectly on TCP options
    except socket.error as sckerror:
        print('Setting socket option failed ! Error: ', sckerror , '\n')

    try:
        if IPV6 == False:
            s.connect((host,port))
        else:
            s.connect((host, port, 0, 0))
    except socket.error as msg:
        if socket.errno.ECONNRESET in msg.args:
            print('Connection reseted by peer side:', msg)
        elif socket.errno.EINTR in msg.args:
            print('A signal was interrupted before any data was available')
        else:
            print('Cannot connect to the server ! ', msg, '\n')
            sys.exit()


    print('Client RCVBuff:', s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))
    print('Client SNDBuff:', s.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF))
    print('Client MSS:', s.getsockopt(socket.SOL_TCP, socket.TCP_MAXSEG), '\n')
    print('Socket connect succesfully')


    intro = str(tim).encode()


    count = 0   #Nr of segments received
    size = 0    #Size od data received
    start_time = time.time()    #Countdown starts here !

    while 1:
        try:
            s.send(intro)
            x = s.recv(buff).decode()
        except socket.error as elol:
            print('Connection closed')
            break

        if not x: break
        data = len(x)
        count = count + 1
        size += data

    stop_time = time.time()
    duration = stop_time - start_time
    trafic = ((size * 8.0) / 1000000) / duration
    print('Reading from socket in: (%f) s, : in (%d) segments (%d)((%f) mbit/s)\n' % (duration, count, size, trafic))
    s.close()


def Main():
    parser = argparse.ArgumentParser(description='IPERF like script, IP address of socket on/to which you want to connect is REQUIRED, also option if you want to run SERVER or CLIENT')
    parser.add_argument('-s', '--server', help = 'If you want to run server', action='store_true' ,default=False)
    parser.add_argument('-c', '--client', help = 'If you want to run client', action='store_true' , default=False)
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

    if args.server and args.TCP and not args.client and not args.UDP:
        ServerTCP(args.port, args.len, args.buffsize, args.nagle, args.ip, args.IPV6)
    elif args.server and args.UDP and not args.client and not args.TCP:
        ServerUDP(args.port, args.mcastport, args.mcastgrp, args.len,args.buffsize, args.timetolive,args.ip, args.multicast, args.IPV6)
    elif args.client and args.UDP and not args.server and not args.TCP:
        ClientUDP(args.ip,args.port, args.mcastport, args.mcastgrp, args.len,args.buffsize,args.timetolive, args.time, args.multicast, args.IPV6)
    elif args.client and args.TCP and not args.server and not args.UDP:
        ClientTCP(args.ip, args.port, args.len, args.buffsize,args.time, args.nagle, args.IPV6)
    elif args.TCP and args.UDP:
        print('You should chose either TCP or UDP ! ')
    elif args.server and args.client:
        print('You need to select either CLIENT or SERVER ! ')
    else:
        print('Something went wrong ! ')

        
if __name__ == '__main__':
    Main()
