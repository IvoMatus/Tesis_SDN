from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import simple_switch_13
from datetime import datetime

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import confusion_matrix,classification_report
from sklearn.metrics import accuracy_score

class SimpleMonitor13(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):

        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        start = datetime.now()

        self.entrenamiento()

        end = datetime.now()
        print("Tiempo de training:  ", (end-start))

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

            self.flow_predict()

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):



        file0 = open("predict_ivo.csv","w")
        file0.write('datapath_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nanosec,byte_count_per_nanosec\n')

        tp_src = 0
        tp_dst = 0
        icmp_code = -1
        icmp_type = -1

        body = ev.msg.body

        for stat in sorted([flow for flow in body if (flow.priority == 1) ], key=lambda flow:
            (flow.match['eth_type'],flow.match['ipv4_src'],flow.match['ipv4_dst'],flow.match['ip_proto'])):
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
                

            file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                .format(ev.msg.datapath.id, ip_src, tp_src,ip_dst, tp_dst, #5
                        stat.match['ip_proto'],icmp_code,icmp_type,  #3   #8
                        stat.duration_sec,stat.flags, stat.packet_count,stat.byte_count, #4 #12
                        packet_count_per_sec,packet_count_per_nanosec,byte_count_per_nanosec))
        file0.close()


    def entrenamiento(self):

        self.logger.info("Entrenando Modelo KNN")

        dataset = pd.read_csv('dataset_ivo.csv',low_memory=False)

        dataset.iloc[:, 1] = dataset.iloc[:, 1].str.replace('.', '')
        dataset.iloc[:, 3] = dataset.iloc[:, 3].str.replace('.', '')
        dataset.iloc[:, -2] = dataset.iloc[:,-2].str.replace(",","")

        X_flow = dataset.iloc[:, :-1].values
        X_flow = X_flow.astype('float32')
        y_flow = dataset.iloc[:, -1].values

        X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.20, random_state=0)


        classifier = KNeighborsClassifier(n_neighbors=4, metric='minkowski')
        self.flow_model = classifier.fit(X_flow_train, y_flow_train)
        y_flow_pred = self.flow_model.predict(X_flow_test)

        self.logger.info("==============================")

        self.logger.info("Matríz de Confusión KNN")
        cm = confusion_matrix(y_flow_test, y_flow_pred)
        self.logger.info(cm)

        acc = accuracy_score(y_flow_test, y_flow_pred)

        self.logger.info("accuracy = {0:.4f} %".format(acc*100))
        fail = 1.0 - acc
        self.logger.info("fail accuracy = {0:.4f} %".format(fail*100))
        self.logger.info("==============================")

    def flow_predict(self):
        try:
            predict_flow_dataset = pd.read_csv('predict_ivo.csv')

            predict_flow_dataset.iloc[:, 1] = predict_flow_dataset.iloc[:, 1].str.replace('.', '')
            predict_flow_dataset.iloc[:, 3] = predict_flow_dataset.iloc[:, 3].str.replace('.', '')
            predict_flow_dataset.iloc[:, -2] = predict_flow_dataset.iloc[:, -2].replace(",","")

            X_predict_flow = predict_flow_dataset.iloc[:, :].values
            X_predict_flow = X_predict_flow.astype('float32')
            
            y_flow_pred = self.flow_model.predict(X_predict_flow)

            ddos_traffic = 0
            n_datos = int(len(y_flow_pred))
            
            for i in y_flow_pred:
                if i == 1:
                    ddos_traffic += 1
            print("Arreglo de Predicción ",y_flow_pred)
            print("traffic {}".format(ddos_traffic))
            porcentaje = ((n_datos - ddos_traffic) / n_datos)
            print("Acuraccy:  {0:.2f} %".format((porcentaje)*100))
            # for i in y_flow_pred:
            #     if i == 0:
            #         print("ok")
            #     else:
            #         print("opa D:")
            #         ddos_trafic = ddos_trafic + 1
                                
            
            file0 = open("predict_ivo.csv","w")
            file0.write('datapath_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nanosec,byte_count_per_nanosec\n')
            file0.close()
            hub.sleep(3)
        except:
            print("Dataset de predicción vacío!")