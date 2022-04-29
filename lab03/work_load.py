from cmath import exp
from unittest import expectedFailure
from dbus import NameExistsException
import networkx as nx
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import tcp
from ryu.lib import hub
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.lib.packet import ether_types
from collections import defaultdict
from ryu.topology.api import get_host, get_link, get_switch
ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__

topo_events = [event.EventSwitchEnter, event.EventLinkAdd, event.EventPortAdd]


class Workload(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Workload, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        # dpid: datapath
        self.datapaths = {}

        # dpid: {port_no: (tx_bytes, rx_bytes, duration_sec, duration_nsec)}
        self.port_stats = {}

        # (s1, s2): s1.port
        self.ss_port = {}

        # s1,port:s1,s2
        self.sp_ss = {}

        # dpid: (ports linked hosts)
        self.port_info = {}

        self.switch_port = {}

        # host: (dpid, port_no)
        self.host_info = {}

        self.topo_map = nx.Graph()
        self.workload_thread = hub.spawn(self._count_workload)

        self.mac_to_port = {}

        self.sw = {}  # use it to avoid arp loop

        # dpid: {port_no : work_load}
        self.workload = {}

    def _count_workload(self):
        while True:
            for dp in self.datapaths.values():
                self._send_request(dp)
            # self.get_topology(None)
            hub.sleep(4)

    def _send_request(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.workload.setdefault(dpid, {})
        self.port_stats.setdefault(dpid, {})
        # you need to code here to finish mission1
        # of course, you can define new function as you wish
        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                value = (stat.tx_bytes, stat.rx_bytes,
                         stat.duration_sec, stat.duration_nsec)
                if dpid in self.port_stats:
                    # if dpid has record then calculate
                    if port_no in self.port_stats[dpid]:
                        last_bits = (
                            self.port_stats[dpid][port_no][0] + self.port_stats[dpid][port_no][1]) * 8
                        curr_bits = (stat.tx_bytes + stat.rx_bytes) * 8
                        last_duration = self.port_stats[dpid][port_no][2] + \
                            self.port_stats[dpid][port_no][3] * 1e-9
                        curr_duration = stat.duration_sec + stat.duration_nsec * 1e-9
                        work_load = (curr_bits - last_bits) / \
                            (curr_duration - last_duration) * 1e-6
                        self.workload[dpid][port_no] = work_load

                self.port_stats[dpid][port_no] = value

    @set_ev_cls(topo_events)
    def get_topology(self, ev):
        switches = get_switch(self)
        for switch in switches:
            self.datapaths[switch.dp.id] = switch.dp

            self.mac_to_port.setdefault(switch.dp.id, {})
            self.switch_port.setdefault(switch.dp.id, set())

        links = get_link(self)
        for link in links:
            self.topo_map.add_edge(link.src.dpid, link.dst.dpid)
            self.ss_port[(link.src.dpid, link.dst.dpid)] = link.src.port_no
            self.ss_port[(link.dst.dpid, link.src.dpid)] = link.dst.port_no
            self.switch_port[link.src.dpid].add(link.src.port_no)
            self.switch_port[link.dst.dpid].add(link.dst.port_no)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dpid = msg.datapath.id

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        # layer 2 self-learning
        in_port = msg.match['in_port']
        src_mac = eth_pkt.src
        self.mac_to_port.setdefault(dpid, {})
        if src_mac not in self.mac_to_port[dpid]:
            self.mac_to_port[dpid][src_mac] = in_port

        if isinstance(arp_pkt, arp.arp):
            self.handle_arp(msg, arp_pkt)

        if isinstance(ipv4_pkt, ipv4.ipv4):
            self.handle_ipv4(msg, ipv4_pkt)

############################deal with loop############################
    def handle_arp(self, msg, arp_pkt):

        # just your code in exp1 mission2
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        dpid = dp.id
        in_port = msg.match['in_port']

        if in_port not in self.switch_port[dpid]:
            self.host_info[arp_pkt.src_ip] = (dpid, in_port)

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        dst = eth_pkt.dst
        src = eth_pkt.src
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        dpid = dp.id

        arp_dst_ip = arp_pkt.dst_ip
        if (dp.id, src, arp_dst_ip) in self.sw:
            if self.sw[(dp.id, src, arp_dst_ip)] != in_port:
                # drop the packet
                out = parser.OFPPacketOut(
                    datapath=dp,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=[],
                    data=None)
                dp.send_msg(out)
                return
        else:
            self.sw[(dp.id, src, arp_dst_ip)] = in_port

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(dp, 1, match, actions, 90, 180)

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data)
        dp.send_msg(out)

        ############################get shortest(hop) path############################
    def handle_ipv4(self, msg, ipv4_pkt):
        ofp = msg.datapath.ofproto
        parser = msg.datapath.ofproto_parser

        ipv4_src = ipv4_pkt.src
        ipv4_dst = ipv4_pkt.dst

        dpid_begin = self.host_info[ipv4_src][0]
        port_begin = self.host_info[ipv4_src][1]

        dpid_final = self.host_info[ipv4_dst][0]
        port_final = self.host_info[ipv4_dst][1]

        dpid_path = self.shortest_path(dpid_begin, dpid_final)
        if not dpid_path:
            return
        print('path {} -> {}: {}'.format(ipv4_src, ipv4_dst, dpid_path))

        # add flow entry
        for i in range(len(dpid_path)):
            curr_switch = dpid_path[i]

            if i == 0:
                next_switch = dpid_path[i + 1]
                out_port = self.ss_port[(curr_switch, next_switch)]
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(
                    eth_type=0x800, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
                self.add_flow(
                    self.datapaths[curr_switch], 20, match, actions, 300, 600)

            elif i == len(dpid_path) - 1:
                out_port = port_final
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(
                    eth_type=0x800, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
                self.add_flow(
                    self.datapaths[curr_switch], 20, match, actions, 300, 600)

                pre_switch = dpid_path[i - 1]
                out_port = self.ss_port[(curr_switch, pre_switch)]
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(
                    eth_type=0x800, ipv4_src=ipv4_dst, ipv4_dst=ipv4_src)
                self.add_flow(
                    self.datapaths[curr_switch], 20, match, actions, 300, 600)
            else:

                prev_switch = dpid_path[i - 1]
                next_switch = dpid_path[i + 1]

                port1 = self.ss_port[(curr_switch, next_switch)]
                port2 = self.ss_port[(curr_switch, prev_switch)]

                out_port = port1
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(
                    eth_type=0x800, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
                self.add_flow(
                    self.datapaths[curr_switch], 20, match, actions, 300, 600)

                out_port = port2
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(
                    eth_type=0x800, ipv4_src=ipv4_dst, ipv4_dst=ipv4_src)
                self.add_flow(
                    self.datapaths[curr_switch], 20, match, actions, 300, 600)

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:

            data = msg.data
            out_port = port_final
            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(
                datapath=self.datapaths[dpid_final], buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFP_NO_BUFFER, actions=actions, data=data)
            self.datapaths[dpid_final].send_msg(out)
            # print('switch {} -> port {}'.format(dpid_final, port_final))
        else:
            out_port = port_begin
            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(
                datapath=self.datapaths[dpid_final], buffer_id=msg.buffer_id, in_port=msg.match['in_port'], actions=actions, data=data)
            msg.datapath.send_msg(out)

    def shortest_path(self, dpid_begin, dpid_final):
        try:
            paths = list(nx.shortest_simple_paths(
                self.topo_map, dpid_begin, dpid_final))
            path_neck = []
            for i in range(len(paths)):
                neck = []
                for j in range(len(paths[i]) - 1):
                    curr_switch = paths[i][j]
                    next_switch = paths[i][j + 1]

                    curr_port = self.ss_port[(curr_switch, next_switch)]
                    next_port = self.ss_port[(next_switch, curr_switch)]

                    curr_workload = self.workload[curr_switch][curr_port]
                    next_workload = self.workload[next_switch][next_port]

                    aviliable = 1000 - max(curr_workload, next_workload)
                    neck.append(aviliable)
                path_neck.append(min(neck))

            index = path_neck.index(max(path_neck))
            print('max neck: {}'.format(path_neck[index]))
            return paths[index]
        except:
            self.logger.info('host not find/no path')
