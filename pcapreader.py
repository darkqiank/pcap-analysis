# encoding: utf-8
# author by sunguosong
# date: 2020-3-20
# python3.7

import dpkt
import math
import time
import threading
import random
import socket
import struct
import re                # 正则表达式库
import pandas as pd
import collections       #
from icecream import ic

from multiprocessing import Manager, Pool
from functools import reduce, wraps
ic.configureOutput(includeContext=True)

inip_regex = '^(127\.0\.0\.1)|(localhost)|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.' \
             '\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})$'  # \d{1, 3}: 表示1-3位0-9之间的数字

# 正则表达式主要是用于识别内网的地址

def is_inip(ip):
    compile_ip = re.compile(inip_regex)
    return True if compile_ip.match(ip) else False   # 使用正则表达式进行匹配
# 判断ip是否是匹配的

def get_ip_layer(pcapbuf):
    def _wrap_ip_as_eth(ip_pkt):
        # 对非以太网链路（如 DLT_RAW）构造一个最小以太网壳，兼容后续逻辑。
        eth = dpkt.ethernet.Ethernet()
        eth.src = b'\x00' * 6
        eth.dst = b'\x00' * 6
        if isinstance(ip_pkt, dpkt.ip6.IP6):
            eth.type = dpkt.ethernet.ETH_TYPE_IP6
        else:
            eth.type = dpkt.ethernet.ETH_TYPE_IP
        eth.data = ip_pkt
        return eth

    try:
        eth = dpkt.ethernet.Ethernet(pcapbuf)
        if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return eth, eth.data
    except Exception:
        pass

    # DLT_RAW: 包体直接是 IPv4/IPv6，不包含以太网头。
    try:
        ip = dpkt.ip.IP(pcapbuf)
        if getattr(ip, 'v', 0) == 4:
            return _wrap_ip_as_eth(ip), ip
    except Exception:
        pass

    try:
        ip6 = dpkt.ip6.IP6(pcapbuf)
        return _wrap_ip_as_eth(ip6), ip6
    except Exception:
        pass

    # DLT_LINUX_SLL 等 cooked capture。
    try:
        sll = dpkt.sll.SLL(pcapbuf)
        if isinstance(sll.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return _wrap_ip_as_eth(sll.data), sll.data
    except Exception:
        pass

    return None, None


def get_random_ip(ip_pool='0.0.0.0/0'):
    ip_pool = [ip_pool]                                                  # 使用0.0.0.0/0初始化了一个ip_pool
    str_ip = ip_pool[random.randint(0, len(ip_pool) - 1)]
    str_ip_addr = str_ip.split('/')[0]
    str_ip_mask = str_ip.split('/')[1]
    ip_addr = struct.unpack('>I', socket.inet_aton(str_ip_addr))[0]      # > 表示大端模式
    mask = 0x0
    for i in range(31, 31 - int(str_ip_mask), -1):  # 负数表示从大到小地往下递减
    #for i in range(31, 2, -1):
        mask = mask | (1 << i)
    ip_addr_min = ip_addr & (mask & 0xffffffff)
    ip_addr_max = ip_addr | (~mask & 0xffffffff)
    return struct.pack('>I', random.randint(ip_addr_min, ip_addr_max))   # 从随机化的范围中取出一组数据


def get_random_mac():
    _mac_1 = random.randint(0, 0xffffffff)
    _mac_2 = random.randint(0, 0xffff)
    _mac = _mac_2 << 32 | _mac_1
    return struct.pack('>q', _mac)[2:7]                                  # 返回6个字节的mac


def get_random_port():
    return random.randint(0, 65535)


class Referrence():                                                      # 这个类是可以使用参数进行初始化的
    def __init__(self, val):
        self.__val = val

    def val(self):
        return self.__val

    def setval(self, val):
        self.__val = val


class PcapReader:
    def __init__(self, file_path, max_data=3000000, label=None, super_detailed=True, forbid443=False):
        self.__file_path = file_path
        self.__child_pcap = []                     # __child_pcap是一个列表
        self.__child_label = []                    #
        self.__session_id = {}
        self.__max_data = max_data
        self.__label = label
        self.__super_detailed = super_detailed
        self.__tot_session_num = 0
        self.__forbid443 = forbid443
        self.__four_tuple = []

    def __create_pcap_reader(self, file_obj):
        # 通过文件头魔数优先识别格式，避免异常回退时文件指针位置异常。
        magic = file_obj.read(4)
        file_obj.seek(0)
        if magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'):
            return dpkt.pcap.Reader(file_obj)
        if magic == b'\x0a\x0d\x0d\x0a':
            return dpkt.pcapng.Reader(file_obj)

        # 无法通过魔数判断时，按 pcap -> pcapng 顺序兜底尝试。
        for reader_cls in (dpkt.pcap.Reader, dpkt.pcapng.Reader):
            try:
                file_obj.seek(0)
                return reader_cls(file_obj)
            except Exception:
                continue
        raise ValueError("Unsupported capture file format")

    def split_by_time(self, _time):
        self.__child_pcap[:] = []
        try:
            with open(self.__file_path, 'rb') as f:
                __pcap = self.__create_pcap_reader(f)
                first_ts = float(0.0)
                __child_buf = []
                for (ts, buf) in __pcap:
                    ts = float(ts)
                    if (first_ts == 0):
                        first_ts = ts
                    if ts - first_ts <= _time:                 # _time为划分的时间区间
                        __child_buf.append((ts, buf))
                    else:

                        self.__child_pcap.append(__child_buf)  # 蒋列表挂载到列表上, __child_buf是一个列表
                        __child_buf = []
                        __child_buf.append((ts, buf))
                        while (ts - first_ts > _time):
                            first_ts += _time

                self.__child_pcap.append(__child_buf)          # 将最后一个__child_buf挂载上去
        except Exception as e:
            print("Error: ", e)

    def __split_by_session(self, __pcap_container, __session_container,    # __pcap_container表示读取的pcap文件
                           maxpkt, cnt_referrence, id_dict):               # 参数是一个关于会话的字典
        id_dict = id_dict
        cnt = cnt_referrence.val()
        data_cnt = 0
        session_dict = {}

        for (ts, buf) in __pcap_container:                                # __pcap_container是pcap文件
            eth, ip = get_ip_layer(buf)
            protocol = 0
            if ip is None:
                continue
            if isinstance(ip.data, dpkt.tcp.TCP):
                protocol = 'tcp'

            elif isinstance(ip.data, dpkt.udp.UDP):
                protocol = 'udp'

            else:
                continue

                '''
            stream = ip.data.data
            if len(stream) == 0:
                continue
            if (stream[0]) in {20, 21, 22, 23}:
               pass
            else:
                continue
                '''

            trans = ip.data
            if self.__forbid443:
                if trans.sport == 443 or trans.dport == 443:
                    continue
            info_tup_1 = (ip.src, ip.dst, trans.sport, trans.dport, protocol)
            info_tup_2 = (ip.dst, ip.src, trans.dport, trans.sport, protocol)

            if info_tup_1 in session_dict:
                if session_dict[info_tup_1] > 800:
                    continue
                session_dict[info_tup_1] += 1                   # session_dict记录了会话的数量

            elif info_tup_2 in session_dict:
                if session_dict[info_tup_2] > 800:
                    continue
                session_dict[info_tup_2] += 1

            else:
                session_dict[info_tup_1] = 1                     # 对新的会话进行计数

            session_id = 0
            if info_tup_1 in id_dict:
                session_id = id_dict[info_tup_1]
            elif info_tup_2 in id_dict:
                session_id = id_dict[info_tup_2]
            else:
                if self.__super_detailed:
                    if self.__tot_session_num >= 200:
                        continue
                    self.__child_label.append(-1)
                id_dict[info_tup_1] = cnt
                session_id = cnt
                __session_container.append([])
                self.__four_tuple.append(info_tup_1)
                cnt += 1
            # print(len(__session_container[session_id]))
            if 20000 >= len(__session_container[session_id]):
                # print(session_id, info_tup_1, len(__session_container[session_id]))
                if self.__super_detailed:
                    session_tid = 0
                    if info_tup_1 in self.__session_id:
                        session_tid = self.__session_id[info_tup_1]
                    elif info_tup_2 in self.__session_id:
                        session_tid = self.__session_id[info_tup_2]
                    else:
                        if self.__tot_session_num >= 200:
                            continue
                        self.__session_id[info_tup_1] = self.__tot_session_num
                        session_tid = self.__tot_session_num
                        self.__tot_session_num += 1
                    self.__child_label[session_id] = self.__label * 200 + session_tid
                    __session_container[session_id].append((ts, buf))
                else:
                    __session_container[session_id].append((ts, buf))
            data_cnt += 1
            if data_cnt >= self.__max_data:
                break
        cnt_referrence.setval(cnt)

    def __split_by_flow(self, __pcap_container, __flow_container, cnt_referrence):
        id_dict = {}
        cnt = cnt_referrence.val()

        data_cnt = 0
        for (ts, buf) in __pcap_container:
            eth, ip = get_ip_layer(buf)
            protocol = 0
            if ip is None:
                continue
            if isinstance(ip.data, dpkt.tcp.TCP):
                protocol = 'tcp'
            elif isinstance(ip.data, dpkt.udp.UDP):
                protocol = 'udp'
            else:
                continue
            trans = ip.data
            info_tup = (ip.src, ip.dst, trans.sport, trans.dport, protocol)

            session_id = 0
            if info_tup in id_dict:
                session_id = id_dict[info_tup]
            else:
                id_dict[info_tup] = cnt
                session_id = cnt
                __flow_container.append([])                  # 在flow_container中增加了一个列表
                cnt += 1
            __flow_container[session_id].append((ts, buf))
            data_cnt += 1
            if data_cnt >= self.__max_data:
                break
        cnt_referrence.setval(cnt)

    def split_by_session(self, maxpkt=100):
        try:
            with open(self.__file_path, 'rb') as f:   # 将数据包作为一个文件打开
                __pcap = self.__create_pcap_reader(f)      # 读取这个文件

                self.__child_pcap[:] = []
                cnt = Referrence(0)                   # Referrence是一个只有一个值的类, 并初始化为0
                session_dict = {}
                self.__split_by_session(__pcap, self.__child_pcap, maxpkt, cnt, session_dict)

        except Exception as e:
            print("Error: ", e)

    def split_by_flow(self):
        try:
            with open(self.__file_path, 'rb') as f:
                __pcap = self.__create_pcap_reader(f)

                self.__child_pcap[:] = []
                cnt = Referrence(0)                                    # Referrence是只有一个元素的类
                self.__split_by_flow(__pcap, self.__child_pcap, cnt)

        except Exception as e:
            print("Error: ", e)

    def split_by_flow_time(self, maxpkt=100, time_smt=1):
        self.split_by_time(time_smt)
        __flow_container = []
        cnt = Referrence(0)
        for idx in range(self.len()):
            self.__split_by_flow(self.get_child_by_index(idx),   # 在按照时间的分类里面需要按照流进行分类
                                 __flow_container, cnt)

        self.__child_pcap = __flow_container

    def split_by_session_time(self, maxpkt=100, time_smt=1):
        self.split_by_time(time_smt)
        __session_container = []
        cnt = Referrence(0)

        session_dict = {}
        for idx in range(self.len()):
            # print('idx: ', idx)
            self.__split_by_session(self.get_child_by_index(idx),
                                    __session_container, maxpkt, cnt, session_dict)
            # for i in range(len(__session_container)):
            #    print(len(__session_container[i]), end=',')

        # print()
        self.__child_pcap = __session_container

    def len(self):
        return len(self.__child_pcap)

    def get_file_path(self):
        return self.__file_path

    def get_child_by_index(self, index):
        return self.__child_pcap[index]

    def get_ftuple_by_index(self, index):
        return self.__four_tuple[index]

    def get_child_label_by_index(self, index):
        return self.__child_label[index]

    def printall_by_index(self, index):
        for (ts, buf) in self.__child_pcap[index]:
            print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)), end=' ')
            print(buf)

    def to_csv(self):
        pass


class PcapAnalyzer():
    def __init__(self, pcap_path, ip_src=0, label=None, super_detail=True, forbid443=False):
        self.__pcap = PcapReader(pcap_path, label=label, super_detailed=super_detail, forbid443=forbid443) # __pcap是一个pcap读取类
        self.__method = 0
        self.__dropnum = 0
        self.__ip_src = ip_src
        self.__timesmt = 0
        self.__len = 0
        self.__pkt_in = []
        self.__pkt_out = []
        self.__ts_in = []
        self.__ts_out = []
        self.__pktlen_in = []
        self.__pktlen_out = []
        self.__label = label
        self.__super_detail = super_detail

    def set_method(self, method):
        self.__method = method

    def set_dropnum(self, dropnum):
        self.__dropnum = dropnum

    def __guess_ipsrc(self):
        if self.__ip_src != 0:
            return
        else:
            _dict = {}
            self.__pcap.split_by_time(10000000)                                       # 分割的方法在类__pcap里面
            if self.__pcap.len() > 0:
                for (ts, pkt) in self.__pcap.get_child_by_index(0):
                    _, ip = get_ip_layer(pkt)
                    if ip is not None:
                        _dict[ip.src] = _dict[ip.src] + 1 if ip.src in _dict else 1
                _dict = sorted(_dict, key=_dict.get, reverse=True)

                for i in range(len(_dict)):
                    if is_inip(socket.inet_ntop(socket.AF_INET, _dict[i])):    # network to presentation
                        self.__ip_src = _dict[i]
                        break
                if self.__ip_src == 0:
                    try:
                        self.__ip_src = _dict[0]
                    except Exception as e:
                        self.__ip_src = socket.inet_pton(socket.AF_INET, "0.0.0.0")
            else:
                self.__ip_src = socket.inet_pton(socket.AF_INET, "0.0.0.0")

    def __ip_filter(self):
        for index in range(self.__pcap.len()):
            pkt_in_list = []
            pkt_out_list = []
            ts_in_list = []
            ts_out_list = []
            pktlen_in_list = []
            pktlen_out_list = []

            if len(self.__pcap.get_child_by_index(index)) < self.__dropnum:  # 数据太少了, 就进行丢弃
                continue

            for (ts, pkt) in self.__pcap.get_child_by_index(index):
                _, ip = get_ip_layer(pkt)                              # pkt值得是pcap buf, 这里的IP指的是IP层的数据
                if ip is not None:
                    if ip.src == self.__ip_src:
                        pkt_out_list.append(ip)                        # pkt_out_list 就是一个list
                        ts_out_list.append(ts)
                        pktlen_out_list.append(len(pkt))

                    elif ip.dst == self.__ip_src:
                        pkt_in_list.append(ip)                           # ip
                        ts_in_list.append(ts)                            # 时间
                        pktlen_in_list.append(len(pkt))                  # 包的长度

            self.__pkt_in.append(pkt_in_list)                             #
            self.__pkt_out.append(pkt_out_list)
            self.__ts_in.append(ts_in_list)
            self.__ts_out.append(ts_out_list)
            self.__pktlen_in.append(pktlen_in_list)
            self.__pktlen_out.append(pktlen_out_list)

            self.__pkt_in.append(pkt_out_list)
            self.__pkt_out.append(pkt_in_list)
            self.__ts_in.append(ts_out_list)
            self.__ts_out.append(ts_in_list)
            self.__pktlen_in.append(pktlen_out_list)
            self.__pktlen_out.append(pktlen_in_list)

            self.__len = len(self.__pkt_in)

    def sum(self):
        return self.__len

    def init(self, features_option=False):
        # print("FILE:", self.__pcap.get_file_path())
        if features_option:
            self.__guess_ipsrc()
        if self.__method == 'time':
            self.__pcap.split_by_time(self.__timesmt)
        elif self.__method == 'session':
            self.__pcap.split_by_session(self.__maxpkt)
        elif self.__method == 'session-time':
            self.__pcap.split_by_session_time(self.__maxpkt, self.__timesmt)
        elif self.__method == 'flow-time':
            self.__pcap.split_by_flow_time(self.__maxpkt, self.__timesmt)
        if features_option:
            self.__ip_filter()

    def set_time_smt(self, timesmt):
        self.__timesmt = timesmt

    def set_session(self, maxpkt):
        self.__maxpkt = maxpkt

    def set_session_time(self, maxpkt, timesmt):
        self.__maxpkt = maxpkt
        self.__timesmt = timesmt

    def get_pktnum_in_out(self):
        _pktnums_in = []
        _pktnums_out = []

        for i in range(self.__len):
            _pktnums_in.append(len(self.__pkt_in[i]))
            _pktnums_out.append(len(self.__pkt_out[i]))

        return _pktnums_in, _pktnums_out

    def get_avepktlen_in_out(self):
        _pktlen_in = []
        _pktlen_out = []

        for i in range(self.__len):
            def func(F):
                return reduce(lambda x, y: x + y, F) \
                    if len(F) > 0 else 0

            tot_in = func(self.__pktlen_in[i])
            tot_out = func(self.__pktlen_out[i])

            _pktlen_in.append(1.0 * tot_in / len(self.__pkt_in[i]) if len(self.__pkt_in[i]) else 0)
            _pktlen_out.append(1.0 * tot_out / len(self.__pkt_out[i]) if len(self.__pkt_out[i]) else 0)

        return _pktlen_in, _pktlen_out

    def get_maxpktlen_in_out(self):
        #def func(F):
        #    F = map(lambda x: max(x, key = lambda x: len(x.data.data)) if len(x) > 0 else None, F)
        #    return list(map(lambda x: len(x.data.data) if x is not None else 0 , F))
        def func(F):
            return list(map(lambda x: max(x) if len(x) > 0 else 0, F))

        _pktlenmax_in = func(self.__pktlen_in)                                 # __pkt_len是一个列表
        _pktlenmax_out = func(self.__pktlen_out)

        return _pktlenmax_in, _pktlenmax_out

    def get_minpktlen_in_out(self):
        # def func(F):
        #    F = map(lambda x: min(x, key = lambda x: len(x.data.data)) if len(x) > 0 else None, F)
        #    return list(map(lambda x: len(x.data.data) if x is not None else 0 , F))
        def func(F):
            return list(map(lambda x: min(x) if len(x) > 0 else 0, F))

        _pktlenmin_in = func(self.__pktlen_in)
        _pktlenmin_out = func(self.__pktlen_out)

        return _pktlenmin_in, _pktlenmin_out

    def get_entropy_pktlen_in_out(self):
        def _log_mapreduce(F):
            return reduce(lambda x, y: x + y, map(lambda x: math.log(len(x.data.data) + 0.000001), F)) \
                if len(F) > 0 else 0

        def _map_entropy(F):
            return list(map(lambda x: _log_mapreduce(x), F))

        _pktlenentropy_in = _map_entropy(self.__pkt_in)
        _pktlenentropy_out = _map_entropy(self.__pkt_out)

        return _pktlenentropy_in, _pktlenentropy_out

    def get_miniat_in_out(self):
        def func(F):
            return 0 if len(F) <= 1 else (min(list(F[i + 1] - F[i] for i in range(0, len(F) - 1))))

        def mapfunc(F):
            return list(map(lambda x: func(x), F))

        _miniat_in = mapfunc(self.__ts_in)
        _miniat_out = mapfunc(self.__ts_out)

        return _miniat_in, _miniat_out

    def get_maxiat_in_out(self):
        def func(F):
            return 0 if len(F) <= 1 else (max(list(F[i + 1] - F[i] for i in range(0, len(F) - 1))))

        def mapfunc(F):
            return list(map(lambda x: func(x), F))

        _maxiat_in = mapfunc(self.__ts_in)
        _maxiat_out = mapfunc(self.__ts_out)

        return _maxiat_in, _maxiat_out

    def get_port_in_out(self):
        _port_in = []
        _port_out = []

        for i in range(self.__len):
            _port_in_child = []
            _port_out_child = []

            for item in self.__pkt_in[i]:
                if not (isinstance(item.data, dpkt.tcp.TCP) or isinstance(item.data, dpkt.udp.UDP)):
                    continue
                trans = item.data
                _port_in_child.append(trans.sport)

            for item in self.__pkt_out[i]:
                if not (isinstance(item.data, dpkt.tcp.TCP) or isinstance(item.data, dpkt.udp.UDP)):
                    continue
                trans = item.data
                _port_out_child.append(trans.sport)

            _port_in.append(_port_in_child)
            _port_out.append(_port_out_child)

        return _port_in, _port_out

    def get_portmode_in_out(self):
        _port_in, _port_out = self.get_port_in_out()       # 这个函数返回关于端口号的列表

        def func(F):
            return list(map(lambda x: pd.Series(data=x).mode()[0] if len(x) > 0 else 0, F))

        _gm_in = func(_port_in)
        _gm_out = func(_port_out)

        return _gm_in, _gm_out

    def __get_packet_shuffle(self, eth, ip, need_shuffled_ref, _shuffle_map, ipsrc_shuffle=False, ipdst_shuffle=False,
                             sport_shuffle=False, dport_shuffle=False):
        if need_shuffled_ref.val():
            if ipsrc_shuffle:
                _shuffle_map[ip.src] = get_random_ip()
                # _shuffle_map[eth.src] = get_random_mac()
            if ipdst_shuffle:
                _shuffle_map[ip.dst] = get_random_ip()
                # _shuffle_map[eth.dst] = get_random_mac()
            if sport_shuffle:
                if ip.data.sport >= 5000:
                    _shuffle_map[ip.data.sport] = get_random_port()
                else:
                    _shuffle_map[ip.data.sport] = ip.data.sport
                # _shuffle_map[ip.data.sport] = get_random_port()
            if dport_shuffle:
                if ip.data.dport >= 5000:
                    _shuffle_map[ip.data.dport] = get_random_port()
                else:
                    _shuffle_map[ip.data.dport] = ip.data.dport
                # _shuffle_map[ip.data.dport] = ip.data.dport
            need_shuffled_ref.setval(False)

        if ipsrc_shuffle:
            ip.src = _shuffle_map[ip.src]

            eth.src = get_random_mac()
        if ipdst_shuffle:
            ip.dst = _shuffle_map[ip.dst]
            eth.dst = get_random_mac()
        if sport_shuffle:
            ip.data.sport = _shuffle_map[ip.data.sport]
        if dport_shuffle:
            ip.data.dport = _shuffle_map[ip.data.dport]

        return eth

    def get_binary(self, buflen=1500, ipsrc_shuffle=False, ipdst_shuffle=False,
                   sport_shuffle=False, dport_shuffle=False, multi_track=1, data_multiple=1,
                   max_data=30000, l7=True, detail=False):
        bins = []
        labels = []
        f_tuple = []
        tot_cnt = 0
        fst_index = 0
        print(self.__pcap.len(), detail)         # 这里的长度是__child_pcap的长度, len()是自己定义的一个函数
        for index in range(self.__pcap.len()):
            bin = []                             # 这里的bin是一个列表
            if detail:
                bin_detail = []
                bins.append(bin_detail)          # bins列表里面又存放了一个数据列表
                f_tuple.append((self.__pcap.get_ftuple_by_index(index), len(self.__pcap.get_child_by_index(index))))
            label = 0
            if self.__super_detail:
                label = self.__pcap.get_child_label_by_index(index)
            else:
                label = self.__label

            curlen = buflen * multi_track
            tracks = multi_track
            need_shuffled = True
            multiple = data_multiple
            _shuffle_map = {}
            # print(len(self.__pcap.get_child_by_index(index)))

            for __index in range(len(self.__pcap.get_child_by_index(index))):
                (ts, pkt) = self.__pcap.get_child_by_index(index)[__index]
                eth, ip = get_ip_layer(pkt)

                if ip is not None:
                    # if ip.src == self.__ip_src or ip.dst == self.__ip_src:
                    if l7:
                        tcp = ip.data
                        if tcp is not None:
                            app = tcp.data
                            if app is not None:
                                _pktlist = list(app)
                                _pktlist_len = len(_pktlist)
                                if _pktlist_len < 5 or _pktlist_len > 12000:
                                    continue
                            else:
                                continue
                        else:
                            continue
                    else:

                        if not (isinstance(ip.data, dpkt.tcp.TCP) or isinstance(ip.data, dpkt.udp.UDP)):
                            continue

                        buf = dpkt.ethernet.Ethernet.pack(eth)
                        _pktlist = list(buf)                         # 将buf转化为一个list
                        _pktlist_len = len(_pktlist)

                    if _pktlist_len > buflen:
                        bin += _pktlist[0:buflen]
                    else:
                        bin += _pktlist
                        bin += [0 for _ in range(buflen - _pktlist_len)]  # 不足的部分使用零进行填充

                    tracks -= 1
                    curlen -= buflen
                    if tracks <= 0:
                        if curlen > 0:
                            bin += [0 for _ in range(curlen)]
                        tot_cnt += 1
                        if detail:
                            bin_detail.append(bin)
                        else:
                            bins.append(bin)
                            labels.append(label)

                        multiple -= 1
                        if multiple <= 0:
                            break

                        bin = []
                        curlen = buflen * multi_track
                        tracks = multi_track
                        # __index -= 3

            if curlen > 0 and curlen < buflen * multi_track:
                bin += [0 for _ in range(curlen)]
                tot_cnt += 1
                if detail:
                    bin_detail.append(bin)
                else:
                    bins.append(bin)
                    labels.append(label)

            if tot_cnt >= max_data:
                break
        if detail:
            return bins, f_tuple        # 返回原始数据和对应的五元组
        else:
            return bins, labels         # 返回原始数据和对应的标签

    def test(self, d):
        print('test!', d)
        return None, None


class PcapAnalyzerManager():                                                # 类PcapAnalyzerManager
    def __init__(self, method='time', maxpkt=50, dropnum=0,
                 time_smt=1, name="PcapAnalyzerManager", forbid443=False):
        self.__name = name
        self.__method = method
        self.__time_smt = time_smt
        self.__maxpkt = maxpkt
        self.__dropnum = dropnum
        self.__trunc_len = 0
        self.__analyzer_rep = []           # 是一个列表
        self.__label = []
        self.__ipsrc = []
        self.__features = pd.DataFrame()
        self.__operations = collections.OrderedDict()
        self.__param = collections.OrderedDict()
        self.__forbid443 = forbid443

    def clear(self):
        self.__analyzer_rep = []
        self.__label = []
        self.__ipsrc = []
        self.__features = pd.DataFrame()
        self.__operations = collections.OrderedDict()
        self.__param = collections.OrderedDict()

    def __manager_all(func):                                                # 管理函数管理所有的解析函数
        @wraps(func)                                                        # wraps将装饰函数的数据复制到包装函数
        def manager_wrap(self, *args, **kwargs):
            column_in, column_out = func(self, *args, **kwargs)             # 标准的包装函数的写法
            self.__param[func.__name__] = (args, kwargs)                    # __param是一个字典
            self.__operations[func.__name__] = (column_in, column_out)      # __operations是一个字典

        return manager_wrap

    def name(self):
        return self.__name

    def __start_workflow(self, file_path, ip_src=0, features_option=False, label=None):
        analyzer = PcapAnalyzer(file_path, ip_src, label=label, super_detail=False, forbid443=self.__forbid443)
        analyzer.set_method(self.__method)                      # self.__method在初始化函数里面指定
        if self.__method == 'time':
            analyzer.set_time_smt(self.__time_smt)
        elif self.__method == 'session':
            analyzer.set_session(self.__maxpkt)
        elif self.__method == 'session-time':
            analyzer.set_session_time(self.__maxpkt, self.__time_smt)
        elif self.__method == 'flow-time':
            analyzer.set_session_time(self.__maxpkt, self.__time_smt)
        else:
            exit(-1)
        analyzer.set_dropnum(self.__dropnum)
        analyzer.init(features_option=features_option)

        return analyzer                                                   # 返回一个pcap分析器

    def append(self, file_path, label, ip_src=0):
        self.__analyzer_rep.append(file_path)
        self.__label.append(label)
        self.__ipsrc.append(ip_src)

    @__manager_all
    def test(self):
        print("aksjd")
        pass

    @__manager_all
    def get_portmode_in_out(self):
        return "port_in", "port_out"

    @__manager_all
    def get_pktnum_in_out(self):
        return "pktnum_in", "pktnum_out"

    @__manager_all
    def get_avepktlen_in_out(self):
        return "avelen_in", "avelen_out"

    @__manager_all
    def get_maxpktlen_in_out(self):
        return "maxlen_in", "maxlen_out"

    @__manager_all
    def get_minpktlen_in_out(self):
        return "minlen_in", "minlen_out"

    @__manager_all
    def get_entropy_pktlen_in_out(self):
        return "entropylen_in", "entropylen_out"

    @__manager_all
    def get_miniat_in_out(self):
        return "miniat_in", "miniat_out"

    @__manager_all
    def get_maxiat_in_out(self):
        return "maxiat_in", "maxiat_out"

    @__manager_all
    def get_binary(self, buflen=1500, ipsrc_shuffle=False, ipdst_shuffle=False,
                   sport_shuffle=False, dport_shuffle=False):                   # 这里设定了默认参数

        '''
        _x = []
        _y = []
        self.__trunc_len = buflen
        for i in range(len(self.__analyzer_rep)):
            analyzer = self.__start_workflow(self.__analyzer_rep[i])
            _t = analyzer.get_binary(buflen, ipsrc_shuffle, ipdst_shuffle,
                                     sport_shuffle, dport_shuffle)
            _x += _t
            _y += [self.__label[i] for _ in range(len(_t))]

        return _x, _y

        :param buflen:
        :param ipsrc_shuffle:
        :param ipdst_shuffle:
        :param sport_shuffle:
        :param dport_shuffle:
        :return:
        '''

        return "binary", None

    def to_csv(self, path):
        try:
            self.__features.to_csv(path, header=0, index=0)
        except Exception as error:
            print("[Error][{0}]: ".format(self.__name), error)

    def to_excel(self, path):
        try:
            self.__features.to_excel(path)
        except Exception as error:
            print("[Error][{0}]: ".format(self.__name), error)

    def binary(self, buflen, ipsrc_shuffle=False, ipdst_shuffle=False,
               sport_shuffle=False, dport_shuffle=False, multi_track=1, data_multiple=1, detail=False):
        _x = []
        _y = []
        self.__trunc_len = buflen
        for i in range(len(self.__analyzer_rep)):    # __analyzer_rep是一个列表, 里面存放的是个pcap文件的路径
            analyzer = self.__start_workflow(self.__analyzer_rep[i], label=self.__label[i])
            _t, _l = analyzer.get_binary(buflen, ipsrc_shuffle, ipdst_shuffle,
                                         sport_shuffle, dport_shuffle, multi_track, data_multiple, detail=detail)
            _x += _t
            _y += _l

        return _x, _y

    def get_sub_binary(self, que, index, ipsrc_shuffle=False, ipdst_shuffle=False,
                       sport_shuffle=False, dport_shuffle=False, multi_track=1, data_multiple=1):
        _x = []
        _y = []

        analyzer = self.__start_workflow(self.__analyzer_rep[index], label=self.__label[index])
        _t, _l = analyzer.get_binary(self.__trunc_len, ipsrc_shuffle, ipdst_shuffle,
                                     sport_shuffle, dport_shuffle, multi_track, data_multiple)
        _x += _t
        _y += _l

        que.put((_x, _y))

    def _merge_binary(self, _x, _y, analyzernum, __fqueue):
        while (analyzernum > 0):
            t1 = time.time()
            (_v1, _v2) = __fqueue.get()
            print(str(time.time() - t1), len(_v1))
            _x += _v1
            _y += _v2
            analyzernum -= 1
            print(analyzernum)

    def get_binary_multiprocess(self, buflen, pnum=2, ipsrc_shuffle=False, ipdst_shuffle=False,
                                sport_shuffle=False, dport_shuffle=False, multi_track=1, data_multiple=1):
        t1 = time.time()
        _x = []
        _y = []

        self.__trunc_len = buflen
        process_pool = Pool(pnum)
        analyzernum = len(self.__analyzer_rep)
        print('########', analyzernum)
        __fqueue = Manager().Queue()

        p = threading.Thread(target=self._merge_binary, args=(_x, _y, analyzernum, __fqueue))
        p.start()

        for i in range(analyzernum):
            process_pool.apply_async(self.get_sub_binary, args=(__fqueue, i, ipsrc_shuffle, ipdst_shuffle,
                                                                sport_shuffle, dport_shuffle, multi_track,
                                                                data_multiple))
        process_pool.close()
        process_pool.join()
        p.join()
        print('end')
        print(time.time() - t1)

        return _x, _y

    def sub_features(self, que, index):
        self.get_portmode_in_out()
        analyzer = self.__start_workflow(self.__analyzer_rep[index], features_option=True)
        df = pd.DataFrame()
        _pktlen = 0
        for key, value in self.__operations.items():

            f = getattr(analyzer, key)                          # getattr获取方法
            _param = self.__param[key]                          # 这里的key是一个函数名

            _pkt_in, _pkt_out = f(*_param[0], **_param[1])      # 这里进行参数的获取
            _pktlen = len(_pkt_in)

            if value[0] is not None:
                df_in = pd.DataFrame(_pkt_in, columns={value[0]})
                if value[1] is not None:
                    df_out = pd.DataFrame(_pkt_out, columns={value[1]})
                    df = pd.concat([df.T, df_in.T, df_out.T]).T
                else:
                    df = pd.concat([df.T, df_in.T]).T

        label = [self.__label[index] for _ in range(_pktlen)]                   # 这里的label是一个list
        df = pd.concat([df.T, pd.DataFrame(label, columns={"label"}).T]).T
        df = df.drop(df[(df.port_in == 0) & (df.port_out == 0)].index)

        que.put(df)

    def features_multiprocess(self, pnum):
        process_pool = Pool(pnum)
        analyzernum = len(self.__analyzer_rep)
        __fqueue = Manager().Queue()

        for i in range(analyzernum):                                           # 在函数__start_workflow中使用了index
            process_pool.apply_async(self.sub_features, args=(__fqueue, i,))   # 使用多个线程的方式进行特征的获取
        process_pool.close()
        process_pool.join()

        for _ in range(analyzernum):
            self.__features = pd.concat([self.__features, __fqueue.get()], axis=0)  # 将进入对列的特征取出来

        return self.__features

    def features(self):                                                                    # 函数features进行特征的获取
        self.get_portmode_in_out()
        for i in range(len(self.__analyzer_rep)):
            analyzer = self.__start_workflow(self.__analyzer_rep[i], features_option=True) # 返回的pcapanalyzer是特征的集合
            df = pd.DataFrame()
            _pktlen = 0
            for key, value in self.__operations.items():

                f = getattr(analyzer, key)
                _param = self.__param[key]

                _pkt_in, _pkt_out = f(*_param[0], **_param[1])                              # 这里进行特征的获取, _pkt_in和_pkt_out都是列表
                _pktlen = len(_pkt_in)

                if value[0] is not None:
                    df_in = pd.DataFrame(_pkt_in, columns={value[0]})        # 给列的名称赋值
                    if value[1] is not None:
                        df_out = pd.DataFrame(_pkt_out, columns={value[1]})
                        df = pd.concat([df.T, df_in.T, df_out.T]).T           # 拼接两个
                    else:
                        df = pd.concat([df.T, df_in.T]).T                      # 拼接一个

            label = [self.__label[i] for _ in range(_pktlen)]
            df = pd.concat([df.T, pd.DataFrame(label, columns={"label"}).T]).T   # 创建一个新的数据并拼接上去
            df = df.drop(df[(df.port_in == 0) & (df.port_out == 0)].index)

            self.__features = pd.concat([self.__features, df], axis=0)          # 这里行数开始增加

        return self.__features







