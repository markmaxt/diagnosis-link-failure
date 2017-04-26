from pox.core import core
#import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import EthAddr,IPAddr
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.core import core
import pox
from pox.lib.util import dpid_to_str, str_to_bool

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.dns import dns
from pox.lib.packet.icmp import icmp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpidToStr
from pox.lib.recoco import Timer
from pox.lib.revent import *
from collections import namedtuple

import pox.openflow.libopenflow_01 as of
import numpy as np

import threading
import time
import copy

import random

log = core.getLogger()

global dpid_to_connection
dpid_to_connection = {}
global timestamp_rec
timestamp_rec = 9999999999.99
global dstvip
dstvip = None

def pack_packet(dstip,packet_type):
    icmp = pkt.icmp()
    icmp.type = pkt.TYPE_ECHO_REQUEST
    echo = pkt.ICMP.echo(payload = "0123456789")
    icmp.payload = echo
    log.debug("This is the icmp payload %s",icmp.payload)

    #Create IP payload
    ipp = pkt.ipv4()
    ipp.protocol = ipp.ICMP_PROTOCOL
    ipp.srcip = IPAddr('10.0.0.100')
    if packet_type == 1:
        ipp.dstip = IPAddr(dstip)
    ipp.payload = icmp
    log.debug("This is the ip payload %s",ipp.payload)

    #Create Ethernet Payload
    e = pkt.ethernet()
    e.src = EthAddr('0:0:0:0:0:0')
    e.dst = ETHER_BROADCAST
    e.type = e.IP_TYPE
    e.payload = ipp
    log.debug("This is the ethernet payload %s",e.payload)

    #Send it to first inport port
    msg = of.ofp_packet_out()
    msg.actions.append(of.ofp_action_output(port=2))
    msg.actions.append(of.ofp_action_nw_tos(nw_tos=0))

    msg.data = e.pack()
    msg.in_port = of.OFPP_NONE
    run_time=1
    dpid_to_connection[10].send(msg)

class Test(threading.Thread):
    def __init__(self,time):
        threading.Thread.__init__(self)
        self._run_time = time


    def run(self):
        global mutex
        vip = []
        vip_to_switch = ['s10', 's5', 's2', 's1', 's3', 's4', 's2', 's7', 's1', 's6', 's5', 's3', 's8', 's1', 's6', 's4', 's9', 's6']
        for i in range(18):
            vip.append('10.0.0.%s' % str(i+101))
        for i in range(10000):
          if 10 in dpid_to_connection:
              mutex.acquire()
              pack_packet('10.0.0.0', 0)
              now = time.time()
              global timestamp_rec
              #log.info('timestamp_rec is %s!',timestamp_rec)
              if timestamp_rec + 1 < now:
                  #log.info(" chu da shi la !!!!!")
                  endpoint=[1,18]
                  while endpoint[1]-endpoint[0] > 1:
                      v = (endpoint[1] + endpoint[0]) / 2
                      dstip = str(vip[v-1])
                      dstipv = dstip.split('.')
                      ipv = int(dstipv[3]) - 100
                      for i in range(100):
                          pack_packet(dstip, 1)    
                      time.sleep(0.1)
                      global dstvip
                      if dstvip == dstip:
                          endpoint[0] = ipv
                      else:
                          endpoint[1] = ipv
                      #log.info("range : %s to %s",endpoint[0], endpoint[1])
                  dstvip = None
                  log.info("link failure between %s and %s",vip_to_switch[endpoint[0]-1],vip_to_switch[endpoint[1]-1])                  
              mutex.release()
          time.sleep(self._run_time)

class LinkEvent (Event):

    #Link up/down event

    def __init__ (self, add, link):
        Event.__init__(self)
        self.link = link
        self.added = add
        self.removed = not add

    def port_for_dpid (self, dpid):
        if self.link.dpid1 == dpid:
            return self.link.port1
        if self.link.dpid2 == dpid:
            return self.link.port2
        return None

class Link (namedtuple("LinkBase",("dpid1","port1","dpid2","port2"))):
  @property
  def uni (self):
    """
    Returns a "unidirectional" version of this link

    The unidirectional versions of symmetric keys will be equal
    """
    pairs = list(self.end)
    pairs.sort()
    return Link(pairs[0][0],pairs[0][1],pairs[1][0],pairs[1][1])

  @property
  def end (self):
    return ((self[0],self[1]),(self[2],self[3]))

  def __str__ (self):
    return "%s.%s -> %s.%s" % (dpid_to_str(self[0]),self[1],
                               dpid_to_str(self[2]),self[3])

  def __repr__ (self):
    return "Link(dpid1=%s,port1=%s, dpid2=%s,port2=%s)" % (self.dpid1,
        self.port1, self.dpid2, self.port2)

    
def _handle_ConnectionUp(event):
    global dpid_to_connection
    dpid_to_connection[event.dpid] = event.connection
    log.info("controller is up: %s",event.connection)

def clockwise(event, priority, idle, hard, tos, new_tos, out_port):
    msg = of.ofp_flow_mod()
    msg.priority = priority
    msg.idle_timeout=idle
    msg.hard_timeout=hard
    msg.match.dl_type = 0x0800
    msg.match.dl_src = EthAddr('0:0:0:0:0:0')
    msg.match.nw_src = IPAddr('10.0.0.100')
    msg.match.nw_tos = tos
    msg.actions.append(of.ofp_action_nw_tos(nw_tos=new_tos))
    msg.actions.append(of.ofp_action_output(port = out_port))
    event.connection.send(msg)

def change_direction(event, priority, idle, hard, tos, new_tos, dstip, IPB, out_port):
    msg = of.ofp_flow_mod()
    msg.priority = priority
    msg.idle_timeout=idle
    msg.hard_timeout=hard
    msg.match.dl_type = 0x0800
    msg.match.dl_src = EthAddr('0:0:0:0:0:0')
    msg.match.nw_src = IPAddr('10.0.0.100')
    msg.match.nw_dst = IPAddr(dstip)
    msg.match.nw_tos = tos
    msg.actions.append(of.ofp_action_nw_tos(nw_tos=new_tos))
    msg.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(IPB)))
    msg.actions.append(of.ofp_action_output(port = out_port))
    event.connection.send(msg)

def counter_clockwise(event, priority, idle, hard, tos, new_tos, out_port):
    msg = of.ofp_flow_mod()
    msg.priority = priority
    msg.idle_timeout=idle
    msg.hard_timeout=hard
    msg.match.dl_type = 0x0800
    msg.match.dl_src = EthAddr('0:0:0:0:0:0')
    msg.match.nw_src = IPAddr('10.0.0.120')
    msg.match.nw_tos = tos
    msg.actions.append(of.ofp_action_nw_tos(nw_tos=new_tos))
    msg.actions.append(of.ofp_action_output(port = out_port))
    event.connection.send(msg)

class Icmp(object):

    _link_timeout = 5          #how long until we consider a link dead
    _timeout_check_period = 5    #how often to check for timeouts

    Link = Link
    
    def __init__(self,link_timeout = None):
        core.openflow.addListeners(self)
        #self.dpid_to_connection = {}
        if link_timeout: self._link_timeout = link_timeout
        self.adjacency = {} #From Link to time.time() stamp
        self.timestamp_rec = None
        #self._dpid = [1,2,3]
        #self.outport = [1,2,2]
        self.ori_dpid = 0
        self.ori_outport = 0
        #self.cp = 0

        # Listen with a high priority(mostly so we get PacketIns early)
        core.listen_to_dependencies(self,
            listen_args={'openflow':{'priority':0xffffffff}})

        Timer(self._timeout_check_period, self._expire_links, recurring=True)

    def _delete_links (self, links):
        for link in links:
            self.adjacency.pop(link, None)
        

    def _expire_links (self):

        #Remove apparently dead links

        now = time.time()

        expired = [link for link, timestamp in self.adjacency.iteritems()
                   if timestamp + self._link_timeout < now]
        #if expired:
            #self.cp += 1
            #if self.cp == 1:
                #for link in expired:
                    #log.info('link timeout: %s',link)

            #self._delete_links(expired)

    def _handle_PacketIn(self,event):
        packet = copy.deepcopy(event.parsed)
        dpid = event.connection.dpid
        inport = event.port

        if isinstance(packet.next,ipv4):

            if not packet.parsed:
                log.warning("%i %i ignoring unparsed packet",dpid,inport)

            if packet.find("icmp"):
                log.debug("Icmp message received")

            log.debug("dpid is %s",dpid)

            if dpid == 4:

                clockwise(event, 5, 0, 0, 0, 8, 2)
                clockwise(event, 5, 0, 0, 16, 16, 5)
                counter_clockwise(event, 5, 0, 0, 0, 0, 4)
                counter_clockwise(event, 5, 0, 0, 16, 16, 3)
                #if packet.next.dstip == '10.0.0.106' or packet.next.dstip == '10.0.0.116':
                change_direction(event, 10, 0, 0, 0, 0, '10.0.0.106', '10.0.0.120', of.OFPP_IN_PORT)
                change_direction(event, 10, 0, 0, 16, 16, '10.0.0.116', '10.0.0.120', of.OFPP_IN_PORT)

            elif dpid == 5:

                clockwise(event, 5, 0, 0, 8, 8, 2)
                clockwise(event, 5, 0, 0, 0, 0, 4)
                counter_clockwise(event, 5, 0, 0, 0, 0, 5)
                counter_clockwise(event, 5, 0, 0, 8, 8, 3)
                #log.info("s5's dstip is %s",packet.next.dstip)
                #if packet.next.dstip == '10.0.0.102' or packet.next.dstip == '10.0.0.111':
                change_direction(event, 10, 0, 0, 0, 0, '10.0.0.102','10.0.0.120', of.OFPP_IN_PORT)
                change_direction(event, 10, 0, 0, 8, 8, '10.0.0.111','10.0.0.120', of.OFPP_IN_PORT)

            elif dpid == 6:

                clockwise(event, 5, 0, 0, 0, 16, 5)
                clockwise(event, 5, 0, 0, 8, 8, 2)
                clockwise(event, 5, 0, 0, 16, 16, 3)
                counter_clockwise(event, 5, 0, 0, 0, 16, 6)
                counter_clockwise(event, 5, 0, 0, 16, 16, 4)
                counter_clockwise(event, 5, 0, 0, 8, 8, 4)
                #if packet.next.dstip == '10.0.0.118' or packet.next.dstip == '10.0.0.110' or packet.next.dstip == '10.0.0.115':
                change_direction(event, 10, 0, 0, 0, 16, '10.0.0.118', '10.0.0.120', of.OFPP_IN_PORT)
                change_direction(event, 10, 0, 0, 8, 8, '10.0.0.110', '10.0.0.120', of.OFPP_IN_PORT)
                
            elif dpid == 9:

                clockwise(event, 5, 0, 0, 16, 0, 3)
                counter_clockwise(event, 5, 0, 0, 16, 16, 2)
                #if packet.next.dstip == '10.0.0.117':
                change_direction(event, 10, 0, 0, 16, 16,'10.0.0.117', '10.0.0.120', of.OFPP_IN_PORT)

            elif dpid == 10:

                clockwise(event, 5, 0, 0, 16, 16, of.OFPP_CONTROLLER)
                counter_clockwise(event, 5, 0, 0, 0, 0, of.OFPP_CONTROLLER)
                log.info
                if packet.next.srcip == '10.0.0.100':
                    global timestamp_rec
                    timestamp_rec = time.time()

                if packet.next.srcip == '10.0.0.120':
                    global dstvip
                    dstvip = packet.next.dstip
                    #log.info("dstvip update: %s",dstvip)
                    
                if packet.next.dstip == '10.0.0.101':
                    change_direction(event, 10, 0, 0, '10.0.0.120', of.OFPP_IN_PORT)

                

            if packet.next.srcip == '10.0.0.100' and packet.next.tos == 16:
                log.info("There is no link failure!")
            #if packet.next.srcip == '10.0.0.120' and packet.next.tos == 0:
                #log.info("yo yo yo yo yo!")

        
                    
            link = Icmp.Link(self.ori_dpid,self.ori_outport,event.dpid,event.port)
            
            if link not in self.adjacency:
                self.adjacency[link] = time.time()
                #log.info('Link detected: %s',link)
            else:
                #Just update timestamp
                self.adjacency[link] = time.time()

            

            return EventHalt

        
def launch():

    core.openflow.addListenerByName("ConnectionUp",_handle_ConnectionUp)
    core.registerNew(Icmp)
    global mutex
    mutex = threading.Lock()
    t1 = Test(0.005)
    t1.start()



          
