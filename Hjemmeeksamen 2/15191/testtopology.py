#!/usr/bin/python

#run the foolowing command
# ./Testtopology  -t 10
# -t  simulation time


import sys
from subprocess import Popen, PIPE
from time import sleep
#import termcolor as T
import argparse
import os
import itertools
import random
import getopt

from mininet.util import dumpNodeConnections
from mininet.net import Mininet
from mininet.log import lg
from mininet.node import OVSKernelSwitch as Switch
from mininet.link import Link, TCLink
from mininet.util import *
from mininet.node import *
from mininet.topo import Topo
from mininet.cli  import *
from mininet.util import makeNumeric, custom

#topology
# C1-------------------------C2-------------------------------C3

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts
        A = self.addHost('A')
        B = self.addHost('B')
        C = self.addHost('C')
        D = self.addHost('D')
        E = self.addHost('E')


        # Add links
        self.addLink (A, B)
        self.addLink (B, C)
        self.addLink (B, D)
        self.addLink (C, D)
        self.addLink (D, E)


topos = { 'mytopo': ( lambda: MyTopo() ) }

def parse_args():
    parser = argparse.ArgumentParser(description="test")
    parser.add_argument('-t',
                        action="store",
                        help="Seconds to run the experiment",
                        default=2)
    args = parser.parse_args()
    args.t = float(args.t)
    return args

def progress(t):
    while t > 0:
        t -= 1
        sys.stdout.flush()
        sleep(1)
    print '\r\n'

def Config(net, args):
    A = net.getNodeByName('A')
    B = net.getNodeByName('B')
    C = net.getNodeByName('C')
    D = net.getNodeByName('D')
    E = net.getNodeByName('E')

    AB = A.intf(A.name+'-eth0')
    BA = B.intf(B.name+'-eth0')

    AB.config(bw=10, delay='100ms', loss=10.0, use_tbf=False)
    BA.config(bw=10, delay='100ms', loss=10.0, use_tbf=False)

    BC = B.intf(B.name+'-eth1')
    CB = C.intf(C.name+'-eth0')

    BC.config(bw=10, delay='100ms', loss=10.0, use_tbf=False)
    CB.config(bw=10, delay='100ms', loss=10.0, use_tbf=False)

    BD = B.intf(B.name+'-eth2')
    DB = D.intf(D.name+'-eth0')

    BD.config(bw=10, delay='100ms', loss=10.0, use_tbf=False)
    DB.config(bw=10, delay='100ms', loss=10.0, use_tbf=False)

    CD = C.intf(C.name+'-eth1')
    DC = D.intf(D.name+'-eth1')

    CD.config(bw=10, delay='100ms', loss=10.0, use_tbf=False)
    DC.config(bw=10, delay='100ms', loss=10.0, use_tbf=False)

    DE = D.intf(D.name+'-eth2')
    ED = E.intf(E.name+'-eth0')

    DE.config(bw=10, delay='100ms', loss=10.0, use_tbf=False)
    ED.config(bw=10, delay='100ms', loss=10.0, use_tbf=False)


    #Enter commands here

    A.cmd('xterm -iconic -T "MIP A" -e ./mip_daemon -d appA routeA fwdA 10 &')
    sleep(1)
    A.cmd('xterm -iconic -T "Route A" -e ./routing_daemon -d routeA fwdA &')
    A.cmd('xterm -iconic  -T "TP A" -e ./transport_daemon -d 1 appA tpA &')
    sleep(1)
    A.cmd('xterm -e ./server tpA 80 &')
    A.cmd('xterm -e ./server tpA 90 &')

    B.cmd('xterm -iconic -T "MIP B"  -e ./mip_daemon -d appB routeB fwdB 20 30 40 &')
    sleep(1)
    B.cmd('xterm -iconic -T "Route B"  -e ./routing_daemon -d routeB fwdB &')
    B.cmd('xterm -iconic  -T "TP B"  -e ./transport_daemon -d 1 appB tpB &')
    sleep(1)
    B.cmd('xterm -e ./server tpB 80&')

    C.cmd('xterm -iconic -T "MIP C"  -e ./mip_daemon -d appC routeC fwdC 50 60 &')
    sleep(1)
    C.cmd('xterm -iconic -T "Route C"  -e ./routing_daemon -d routeC fwdC &')
    C.cmd('xterm -iconic  -T "TP C"  -e ./transport_daemon -d 1 appC tpC &')
    sleep(1)

    D.cmd('xterm -iconic -T "MIP D" -e ./mip_daemon -d appD routeD fwdD 70 80 90 &')
    sleep(1)
    D.cmd('xterm -iconic -T "Route D" -e ./routing_daemon -d routeD fwdD &')
    D.cmd('xterm -iconic -T "TP D" -e ./transport_daemon -d 1 appD tpD &')
    sleep(1)
    D.cmd('xterm -e ./server tpD 80 &')

    E.cmd('xterm -iconic -T "MIP E" -e ./mip_daemon -d appE routeE fwdE 100 &')
    sleep(1)
    E.cmd('xterm -iconic -T "Route E" -e ./routing_daemon -d routeE fwdE &')
    E.cmd('xterm -iconic -T "TP E" -e ./transport_daemon -d 1 appE tpE &')
    sleep(1)
    E.cmd('xterm -e ./server tpE 80 &')
    sleep(1)
    E.cmd('xterm -e ./client tpE 10 90 mip.c &')
    A.cmd('xterm -e ./client tpA 100 80 mip.c &')
    B.cmd('xterm -e ./client tpB 10 80 mip.c &')
    B.cmd('xterm -e ./client tpB 10 90 mip.c &')
    C.cmd('xterm -e ./client tpC 30 80 mip.c &')
    C.cmd('xterm -e ./client tpC 10 90 mip.c &')
    C.cmd('xterm -e ./client tpC 100 80 mip.c &')
    D.cmd('xterm -e ./client tpD 10 80 mip.c &')
    D.cmd('xterm -e ./client tpD 100 80 mip.c &')
    E.cmd('xterm -e ./client tpE 10 80 mip.c ')

    progress(int(args.t))


    #C3.sendInt()
    #A.sendInt()
    #B.sendInt()
    #C.sendInt()
    #D.sendInt()
    #E.sendInt()



def main(argv):
    args = parse_args()
    lg.setLogLevel('info')
    "Create and run experiment"
    topo = MyTopo()

    net = Mininet(topo=topo, link=TCLink, controller = OVSController)

    net.start()
    Config(net,args)
    #dumpNodeConnections(net.hosts)

    net.stop()

if __name__ == '__main__':
    main(sys.argv)
