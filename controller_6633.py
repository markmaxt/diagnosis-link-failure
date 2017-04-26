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
#from pox.lib.packet.vlan import vlan
#from pox.lib.packet.udp import udp
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
        self._dpid = [1,2,3]
        self.outport = [1,2,2]
        self.ori_dpid = 0
        self.ori_outport = 0
        self.cp = 0

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

        #expired = [link for link, timestamp in self.adjacency.iteritems()
        #           if timestamp + self._link_timeout < now]
        #if expired:
        #    self.cp += 1
        #    if self.cp == 1:
        #        for link in expired:
        #            log.info('link timeout: %s',link)

        #    self._delete_links(expired)

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

            if dpid == 1:

                clockwise(event, 5, 0, 0, 0, 0, 5)
                clockwise(event, 5, 0, 0, 8, 8, 6)
                clockwise(event, 5, 0, 0, 16, 16, 6)
                counter_clockwise(event, 5, 0, 0, 0, 0, 4)
                counter_clockwise(event, 5, 0, 0, 8, 8, 3)
                counter_clockwise(event, 5, 0, 0, 16, 8, 2)
                
                
                #if packet.next.dstip == '10.0.0.104' or packet.next.dstip == '10.0.0.109' or packet.next.dstip == '10.0.0.114':
                change_direction(event, 10, 0, 0, 0, 0, '10.0.0.104', '10.0.0.120', of.OFPP_IN_PORT)
                change_direction(event, 10, 0, 0, 8, 8, '10.0.0.109', '10.0.0.120', of.OFPP_IN_PORT)
                change_direction(event, 10, 0, 0, 16, 8, '10.0.0.114', '10.0.0.120', of.OFPP_IN_PORT)

            elif dpid == 2:

                clockwise(event, 5, 0, 0, 0, 0, 2)
                clockwise(event, 5, 0, 0, 8, 8, 3)
                counter_clockwise(event, 5, 0, 0, 0, 0, 5)
                counter_clockwise(event, 5, 0, 0, 8, 0, 4)
                #if packet.next.dstip == '10.0.0.103' or packet.next.dstip == '10.0.0.107':
                change_direction(event, 10, 0, 0, 0, 0, '10.0.0.103', '10.0.0.120', of.OFPP_IN_PORT)
                change_direction(event, 10, 0, 0, 8, 0, '10.0.0.107', '10.0.0.120', of.OFPP_IN_PORT)

            elif dpid == 3:

                clockwise(event, 5, 0, 0, 0, 0, 5)
                clockwise(event, 5, 0, 0, 8, 8, 2)
                counter_clockwise(event, 5, 0, 0, 0, 0, 3)
                counter_clockwise(event, 5, 0, 0, 8, 8, 4)
                #if packet.next.dstip == '10.0.0.105' or packet.next.dstip == '10.0.0.112':
                change_direction(event, 10, 0, 0, 0, 0, '10.0.0.105', '10.0.0.120', of.OFPP_IN_PORT)
                change_direction(event, 10, 0, 0, 8, 8, '10.0.0.112', '10.0.0.120', of.OFPP_IN_PORT)

            elif dpid == 7:

                clockwise(event, 5, 0, 0, 8, 8, 2)
                counter_clockwise(event, 5, 0, 0, 8, 8, 3)
                #if packet.next.dstip == '10.0.0.108':
                change_direction(event, 10, 0, 0, 8, 8, '10.0.0.108', '10.0.0.120', of.OFPP_IN_PORT)

            elif dpid == 8:

                clockwise(event, 5, 0, 0, 8, 16, 2)
                counter_clockwise(event, 5, 0, 0, 8, 8, 3)
                #if packet.next.dstip == '10.0.0.113':
                change_direction(event, 10, 0, 0, 8, 8, '10.0.0.113', '10.0.0.120', of.OFPP_IN_PORT)

                


            #if packet.next.srcip == '10.0.0.120' and packet.next.tos == 0:
                #log.info("la la la la la!")

        
                    
            link = Icmp.Link(self.ori_dpid,self.ori_outport,event.dpid,event.port)
            
            if link not in self.adjacency:
                self.adjacency[link] = time.time()
                #log.info('Link detected: %s',link)
                #self.raiseEventNoErrors(LinkEvent, True, link)
            else:
                #Just update timestamp
                self.adjacency[link] = time.time()

            return EventHalt

        
def launch():

    core.openflow.addListenerByName("ConnectionUp",_handle_ConnectionUp)
    core.registerNew(Icmp)



          
