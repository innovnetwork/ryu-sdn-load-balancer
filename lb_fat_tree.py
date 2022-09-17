# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, ether_types
from ryu.app import simple_switch_13


class SimpleSwitch13(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    VIRTUAL_IP = '10.0.1.1'  # The virtual server IP
    VIRTUAL_MAC  = 'a0:11:00:00:0b:0c'
    counter = 0
    
    SERVERS = {13:{'00:00:00:00:00:01':('10.0.0.1',1),
               '00:00:00:00:00:02':('10.0.0.2',2)
              },
              15:{"00:00:00:00:00:05":("10.0.0.5",1),
                  "00:00:00:00:00:06":("10.0.0.6",2)
              }
            }

    """
    SERVERS = {13:{"00:00:00:00:00:01":("10.0.0.1",1),
                  "00:00:00:00:00:02":("10.0.0.2",2)
                 },
               14:{"00:00:00:00:00:03":("10.0.0.3",1),
                  "00:00:00:00:00:04":("10.0.0.4",2)
                 },
               15:{"00:00:00:00:00:05":("10.0.0.5",1),
                  "00:00:00:00:00:06":("10.0.0.6",2)
                 },
               16:{"00:00:00:00:00:07":("10.0.0.7",1),
                  "00:00:00:00:00:08":("10.0.0.8",2)
                 },
               17:{"00:00:00:00:00:09":("10.0.0.9",1),
                  "00:00:00:00:00:0a":("10.0.0.10",2)
                 }
           }
    """
    selected_switch = 13
    counter_switch = 0

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.stp = kwargs['stplib']

        # Sample of stplib config.
        #  please refer to stplib.Stp.set_config() for details.
        config = {dpid_lib.str_to_dpid('0000000000000001'):
                  {'bridge': {'priority': 0x8000}},
                  dpid_lib.str_to_dpid('0000000000000002'):
                  {'bridge': {'priority': 0x8000}},
                  dpid_lib.str_to_dpid('0000000000000003'):
                  {'bridge': {'priority': 0x8000}},
                  dpid_lib.str_to_dpid('0000000000000004'):
                  {'bridge': {'priority': 0x8000}},
                  dpid_lib.str_to_dpid('0000000000000005'):
                  {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('0000000000000006'):
                  {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('0000000000000007'):
                  {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('0000000000000008'):
                  {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('0000000000000009'):
                  {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('000000000000000a'):
                  {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('000000000000000b'):
                  {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('000000000000000c'):
                  {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('000000000000000d'):
                  {'bridge': {'priority': 0xa000}},
                  dpid_lib.str_to_dpid('000000000000000e'):
                  {'bridge': {'priority': 0xa000}},
                  dpid_lib.str_to_dpid('000000000000000f'):
                  {'bridge': {'priority': 0xa000}},
                  dpid_lib.str_to_dpid('0000000000000010'):
                  {'bridge': {'priority': 0xa000}},
                  dpid_lib.str_to_dpid('0000000000000011'):
                  {'bridge': {'priority': 0xa000}},
                  dpid_lib.str_to_dpid('0000000000000012'):
                  {'bridge': {'priority': 0xa000}},
                  dpid_lib.str_to_dpid('0000000000000013'):
                  {'bridge': {'priority': 0xa000}},
                  dpid_lib.str_to_dpid('0000000000000014'):
                  {'bridge': {'priority': 0xa000}}}
        self.stp.set_config(config)

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)


    def add_flows(self, datapath, priority, match, actions,idle_timeout=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,idle_timeout=idle_timeout,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM)
        datapath.send_msg(mod)


    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src
        
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flows(datapath, 1, match, actions)


        s_filtre = ["33:33","ff:ff"]
        #s_filtre = ["33:33"]
        """
        #if dst[:5] not in s_filtre and src[:5] not in s_filtre and out_port != ofproto.OFPP_FLOOD: 
        if dst[:5] not in s_filtre and src[:5] not in s_filtre: 
            self.logger.info("packet in %s %s %s =>[ %s ]=> %s",src,dst,in_port,dpid,out_port)
        """
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_header=pkt.get_protocols(arp.arp)[0]
            if dpid == self.selected_switch:
                #if arp_header.dst_ip==self.VIRTUAL_IP and arp_header.dst_mac=="00:00:00:00:00:00"  and arp_header.opcode==arp.ARP_REQUEST:
                if arp_header.dst_ip==self.VIRTUAL_IP and arp_header.opcode==arp.ARP_REQUEST:
                    r_arp = self.arp_reply(arp_header.src_ip, arp_header.src_mac)
                    actions = [parser.OFPActionOutput(in_port)]
                    r_eth = r_arp.get_protocol(ethernet.ethernet)
                    server_port = self.SERVERS[self.selected_switch][r_eth.src][1]
                    packet_out = parser.OFPPacketOut(datapath=datapath, in_port=server_port,
                                        data=r_arp.data, actions=actions, 
                                        #buffer_id=0xffffffff
                                        buffer_id=msg.buffer_id
                                        )
                    datapath.send_msg(packet_out)
                    self.logger.info("ARP reply : %s %s %s =>[%s]=> %s",r_eth.src, r_eth.dst, server_port, dpid, in_port)
                    return
        # Handle TCP Packet
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_header = pkt.get_protocol(ipv4.ipv4)
            #self.logger.info("IP V4 : %s \n",ip_header)
            packet_handled = self.ip_packet(datapath, in_port, out_port, ip_header, parser, dst, src)
            if packet_handled:
                #self.counter = (self.counter+1)%len(self.SERVERS)
                return

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])

    def arp_reply(self, dst_ip, dst_mac):
        self.logger.info("ARP request client ip: " + dst_ip + ", client mac: " + dst_mac)
        # Making the load balancer IP as source IP
        
        #server_mac = list(self.SERVERS)[self.counter]
        server_mac = list(self.SERVERS[self.selected_switch])[self.counter]
        pkt = packet.Packet()
        pkt.add_protocol(
            ethernet.ethernet(
                dst=dst_mac, src=server_mac, ethertype=ether_types.ETH_TYPE_ARP)
        )
        pkt.add_protocol(
            arp.arp(opcode=arp.ARP_REPLY, src_mac=server_mac, src_ip=self.VIRTUAL_IP,
                    dst_mac=dst_mac, dst_ip=dst_ip)
        )
        pkt.serialize()
        """
        self.logger.info("Current : Switch = %s Server = %s",self.selected_switch, self.counter+1)
        self.counter += 1
        if self.counter >= len(self.SERVERS[self.selected_switch]):
            self.counter = 0
            self.counter_switch = (self.counter_switch+1)%len(self.SERVERS)
            self.selected_switch = list(self.SERVERS)[self.counter_switch]
            self.logger.info("Next : Switch = %s Server = %s \n",self.selected_switch, self.counter+1)
        #self.counter = (self.counter+1)%len(self.SERVERS)
        """
        return pkt


    def ip_packet(self, datapath, in_port, out_port, ip_header, parser, dst_mac, src_mac):
        packet_handled = False
        if ip_header.dst == self.VIRTUAL_IP and out_port != datapath.ofproto.OFPP_FLOOD:
            server_dst_ip = self.SERVERS[self.selected_switch][dst_mac][0]
            server_out_port = self.SERVERS[self.selected_switch][dst_mac][1]
            # Route to server
            match = parser.OFPMatch(in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    #eth_src=src_mac,
                    eth_dst = dst_mac,
                    #ip_proto=ip_header.proto,
                    vlan_vid=0,
                    ipv4_dst=self.VIRTUAL_IP)

            actions = [parser.OFPActionSetField(ipv4_dst=server_dst_ip),
                       parser.OFPActionOutput(out_port)]

            self.add_flows(datapath, 100, match, actions)
            #self.logger.info("Route to Server: "+str(server_dst_ip) +" from Client : "+str(ip_header.src))

            # Reverse route from server
            match = parser.OFPMatch(in_port=out_port, eth_type=ether_types.ETH_TYPE_IP,
                                    #ip_proto=ip_header.proto,
                                    vlan_vid=0,
                                    ipv4_src=server_dst_ip,
                                    eth_dst=src_mac)
            actions = [parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP),
                       parser.OFPActionOutput(in_port)]

            self.add_flows(datapath, 100, match, actions)
            packet_handled = True
            
            self.logger.info("Current : Switch = %s Server = %s",self.selected_switch, self.counter+1)
            self.counter += 1
            if self.counter >= len(self.SERVERS[self.selected_switch]):
                self.counter = 0
                self.counter_switch = (self.counter_switch+1)%len(self.SERVERS)
                self.selected_switch = list(self.SERVERS)[self.counter_switch]
            self.logger.info("Next : Switch = %s Server = %s \n",self.selected_switch, self.counter+1)
            
        return packet_handled

