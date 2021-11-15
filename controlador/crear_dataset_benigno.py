from operator import attrgetter


import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub


class SimpleMonitor13(simple_switch_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        file0 = open("dataset_flowstats.csv","w")
        file0.write('datapath_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nanosec,byte_count_per_nanosec,label\n')
        file0.close()

        file1 = open("dataset_portstats.csv","w")
        file1.write('datapath_id,tx_bytes,rx_bytes,label\n')
        file1.close()

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):

        tp_src = 0
        tp_dst = 0
        icmp_code = -1
        icmp_type = -1

        file0 = open("dataset_flowstats.csv","a+")
        body = ev.msg.body
        for stat in sorted([flow for flow in body if (flow.priority == 1) ], key=lambda flow:
            (flow.match['ipv4_dst'],flow.match['eth_type'],flow.match['ipv4_src'],flow.match['ip_proto'])):
            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match['ip_proto']
            
            if stat.match['ip_proto'] == 1:  # PUERTO DE DESTINO ICMP
                icmp_code = stat.match['icmpv4_code']
                icmp_type = stat.match['icmpv4_type']

            elif stat.match['ip_proto'] == 6:   #Puerto de destino TCP
                tp_src = stat.match['tcp_src']
                tp_dst = stat.match['tcp_dst']

            elif stat.match['ip_proto'] == 17:  #PUERTO DE DESTINO UDP
                tp_src = stat.match['udp_src']
                tp_dst = stat.match['udp_dst']
            try:
                packet_count_per_sec = stat.packet_count/stat.duration_sec
                packet_count_per_nanosec = stat.packet.count/stat.duration_nsec
            except:
                packet_count_per_sec = 0
                packet_count_per_nanosec = 0            
            try:
                byte_count_per_nanosec = stat.byte_count/stat.duration_nsec
            except:
                byte_count_per_nanosec = 0
                

            file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},0\n"
                .format(ev.msg.datapath.id, ip_src, tp_src,ip_dst, tp_dst, #5
                        stat.match['ip_proto'],icmp_code,icmp_type,  #3   #8
                        stat.duration_sec,stat.flags, stat.packet_count,stat.byte_count, #4 #12
                        packet_count_per_sec,packet_count_per_nanosec,byte_count_per_nanosec))
        file0.close()


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        file1 = open("dataset_portstats.csv","a+")
        for stat in sorted(body, key=attrgetter('port_no')):
            file1.write("{},{},{},{}\n".format(ev.msg.datapath.id,stat.tx_bytes,stat.rx_bytes,0))
        file1.close()
