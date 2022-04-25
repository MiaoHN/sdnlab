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


class Workload(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Workload, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.datapaths = {}  # dpid: datapath
        self.port_stats = {}  # (dpid,port_no):a list of port_stats
        self.link_info = {}  # (s1, s2): s1.port
        self.port_link = {}  # s1,port:s1,s2
        self.port_info = {}  # dpid: (ports linked hosts)
        self.topo_map = nx.Graph()
        self.workload_thread = hub.spawn(self._count_workload)
        self.mac_to_port = {}
        self.sw = {}  # use it to avoid arp loop
        self.weight = 'hop'
        # you need to store workload of every port here
        self.workload = {}  # dpid: {port_no : work_load}

    def _count_workload(self):
        while True:
            for dp in self.datapaths.values():
                self._send_request(dp)
            self.get_topology(None)
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
        # you need to code here to finish mission1
        # of course, you can define new function as you wish
        # for stat in sorted(body, key=attrgetter('port_no')):
        #    port_no = stat.port_no
        #    if port_no != ofproto_v1_3.OFPP_LOCAL:
        #        key = (dpid, port_no)
        #        value = (stat.tx_bytes, stat.rx_bytes,
        #                 stat.duration_sec, stat.duration_nsec)
        #        print(key,end=':')
        #        print(value)

############################detect topology############################
    def get_topology(self, ev):
        """
            Gett topology info to calculate shortest paths.
        """
        _hosts, _switches, _links = None, None, None
        hosts = get_host(self)
        switches = get_switch(self)
        links = get_link(self)

        # update topo_map when topology change
        if [str(x) for x in hosts] == _hosts and [str(x) for x in switches] == _switches and [str(x) for x in
                                                                                              links] == _links:
            return
        _hosts, _switches, _links = [str(x) for x in hosts], [str(
            x) for x in switches], [str(x) for x in links]

        for switch in switches:
            self.port_info.setdefault(switch.dp.id, set())
            # record all ports
            for port in switch.ports:
                self.port_info[switch.dp.id].add(port.port_no)

        for host in hosts:
            # take one ipv4 address as host id
            if host.ipv4:
                self.link_info[(host.port.dpid, host.ipv4[0])
                               ] = host.port.port_no
                self.topo_map.add_edge(
                    host.ipv4[0], host.port.dpid, hop=1, delay=0, is_host=True)
        for link in links:
            # delete ports linked switches
            self.port_info[link.src.dpid].discard(link.src.port_no)
            self.port_info[link.dst.dpid].discard(link.dst.port_no)

            # s1 -> s2: s1.port, s2 -> s1: s2.port
            self.port_link[(link.src.dpid, link.src.port_no)] = (
                link.src.dpid, link.dst.dpid)
            self.port_link[(link.dst.dpid, link.dst.port_no)] = (
                link.dst.dpid, link.src.dpid)

            self.link_info[(link.src.dpid, link.dst.dpid)] = link.src.port_no
            self.link_info[(link.dst.dpid, link.src.dpid)] = link.dst.port_no
            self.topo_map.add_edge(
                link.src.dpid, link.dst.dpid, hop=1, is_host=False)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        dpid = dp.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        pkt_type = eth_pkt.ethertype
        # layer 2 self-learning
        dst_mac = eth_pkt.dst
        src_mac = eth_pkt.src

        if isinstance(arp_pkt, arp.arp):
            self.handle_arp(msg)

        if isinstance(ipv4_pkt, ipv4.ipv4):
            self.handle_ipv4(msg, ipv4_pkt.src, ipv4_pkt.dst, pkt_type)

############################deal with loop############################
    def handle_arp(self, msg):

        # just your code in exp1 mission2

        ############################get shortest(hop) path############################
    def handle_ipv4(self, msg, src_ip, dst_ip, pkt_type):
        parser = msg.datapath.ofproto_parser

        dpid_path = self.shortest_path(src_ip, dst_ip, weight=self.weight)
        if not dpid_path:
            return

        self.path = dpid_path
        # get port path:  h1 -> in_port, s1, out_port -> h2
        port_path = []
        for i in range(1, len(dpid_path) - 1):
            in_port = self.link_info[(dpid_path[i], dpid_path[i - 1])]
            out_port = self.link_info[(dpid_path[i], dpid_path[i + 1])]
            port_path.append((in_port, dpid_path[i], out_port))
        self.show_path(src_ip, dst_ip, port_path)

        # send flow mod
        for node in port_path:
            in_port, dpid, out_port = node
            self.send_flow_mod(parser, dpid, pkt_type,
                               src_ip, dst_ip, in_port, out_port)
            self.send_flow_mod(parser, dpid, pkt_type,
                               dst_ip, src_ip, out_port, in_port)

        # send packet_out
        _, dpid, out_port = port_path[-1]
        dp = self.datapaths[dpid]
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        dp.send_msg(out)

    def shortest_path(self, src, dst, weight='hop'):
        try:
            paths = list(nx.shortest_simple_paths(
                self.topo_map, src, dst, weight=weight))
            return paths[0]
        except:
            self.logger.info('host not find/no path')

    def send_flow_mod(self, parser, dpid, pkt_type, src_ip, dst_ip, in_port, out_port):
        dp = self.datapaths[dpid]
        match = parser.OFPMatch(
            in_port=in_port, eth_type=pkt_type, ipv4_src=src_ip, ipv4_dst=dst_ip)
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(dp, 5, match, actions, 10, 30)

    def show_path(self, src, dst, port_path):
        self.logger.info('path: {} -> {}'.format(src, dst))
        path = src + ' -> '
        for node in port_path:
            path += '{}:s{}:{}'.format(*node) + ' -> '
        path += dst
        self.logger.info(path)
