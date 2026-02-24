# -*- coding:utf8 -*-
from pcapreader import PcapAnalyzerManager
import socket
from icecream import ic
import re
import pandas as pd

ic.configureOutput(includeContext=True)
max_detect_bytes = 150                          # 限定最大检测字节数为150字节

def lcs_func(m, n, min_len=4):
    m_len = 1024
    n_len = 1024
    for i in range(1024):
        if m[1023 - i] == 0:
            m_len -= 1
        else:
            break
    for i in range(1024):
        if n[1023 - i] == 0:
            n_len -= 1
        else:
            break                  # 确定数据的实际可用长度
    m_len = min(max_detect_bytes, m_len)
    n_len = min(max_detect_bytes, n_len)
    dp = [[0 for i in range(m_len + 1)] for j in range(n_len + 1)]
    s_len = min(m_len, n_len)
    for i in range(0,s_len):
        if m[i] == n[i]:
            if i>0:
                dp[i][i] = dp[i-1][i-1] + 1
            else:
                dp[i][i] = 1
    mx = 0                                       # 数据
    pos = (0, 0)                                 # 位置数据
    mx_list = []                                 # 两个列表
    pos_list = []                                # 两个列表
    for i in range(0, n_len):
        for j in range(0, m_len):
            #print(dp[i][j], end=',')
            if mx < dp[i][j]:
                mx = dp[i][j]
                pos = (i, j)
            if dp[i][j] >= min_len:              # min_len定义了相同字符的最小长度
                if dp[i + 1][j + 1] == 0 and dp[i + 1][j] == 0 and dp[i][j + 1] == 0: # dp: duplicate
                    mx_list.append(dp[i][j])     # 只有出现不同了, 才会挂载上去
                    pos_list.append((i, j))
        # print()

    return mx, pos, mx_list, pos_list     # 是相同字符的数量, pos是相同字符的位置, mx_list是相同字符数量列表, pos_list是相同字符位置列表


class Trie:
    def __init__(self):
        self.root = {}                  # root是一个字典
        self.word_end = -1              # 列表中最后一个元素的编号是-1
        self.max_len = 16               # 最大的搜索长度为40

    def insert(self, word):
        curNode = self.root             # curNode是一个字典, self.root是一个字典
        cnt = 0
        for c in word:
            #print(f"c in word ${word} is equal to ")      # '%02x' % a
            #print('%02x' % c)
            if c not in curNode:                          # 这里嵌套的字典可以类比为一棵树
                curNode[c] = {}                           # 将一个空字典赋给字典中的值
            curNode = curNode[c]                          # 字典中的每个值又是一个字典
            #print(f"curNode is equal to ${curNode}")     # 组成了一个嵌套的字典, 将找到的匹配项存储起来

            cnt += 1
            if cnt > self.max_len:
                break

        curNode[self.word_end] = True    # word_end = -1   # 对字典中最后一个值的内容进行写入

    def search(self, word):
        curNode = self.root              # root是一个字典
        cnt = 0
        for c in word:
            if not c in curNode:
                return False
            curNode = curNode[c]         # 将一个字典赋给curNode

            cnt += 1
            if cnt > self.max_len:
                break

        if self.word_end not in curNode:
            return False

        return True

    def start_with(self, prefix):
        curNode = self.root
        cnt = 1
        for c in prefix:
            if not c in curNode:
                return False
            curNode = curNode[c]

            cnt += 1
            if cnt > self.max_len:
                break

        return True

    def get_common_start_with(self, prefix):
        curNode = self.root
        cnt = 1
        res = []
        for c in prefix:
            if c not in curNode:       # 当前节点
                break
            curNode = curNode[c]       # 从嵌套的字典中获取数据
            res.append(c)
            cnt += 1
            if cnt > self.max_len:     # 限定了最大长度为40
                break
        return res                     # 返回一个列表
        # 这个类实现了一组函数           # 从字典树中寻找相同的字符
    def clear_trees(self):
        self.root = {}


def print_func(n, mx, end_pos):        # pos_list里面记录的是end position, 这里的end_pos表示下表的值
    # print(u, v, mx, pos)
    for i in range(mx):
        a = n[end_pos - mx + i + 1]
        if a >= 0x20 and a <= 0x7e:    # 0x20和0x7e是可见字符的范围
            print(chr(a), end='')      # end表示打印的结束符
        else:
            print('.', end='')         # 若是非可见字符串则打印出
    print()
    s = ''
    for i in range(mx):
        a = n[end_pos - mx + i + 1]    # n是一个列表
        s += '%02x' % a                # 以十六进制的形式进行打印
        #print('%02x' % a, end='')     # 知识点: ord函数
    print(s)
    return s


def print_func_binary(n, mx, end_pos):        # pos_list里面记录的是end position, 这里的end_pos表示下表的值
    # print(u, v, mx, pos)
    # for i in range(mx):
    #     a = n[end_pos - mx + i + 1]
    #     if a >= 0x20 and a <= 0x7e:    # 0x20和0x7e是可见字符的范围
    #         print(chr(a), end='')      # end表示打印的结束符
    #     else:
    #         print('.', end='')         # 若是非可见字符串则打印出
    # print()
    record = []
    s = ''
    for i in range(mx):
        a = n[end_pos - mx + i + 1]    # n是一个列表
        s += '%02x' % a                # 以十六进制的形式进行打印
        #print('%02x' % a, end='')     # 知识点: ord函数

    print("iptables -I self_control  -m string --hex-string \" |" + str(s) + "| \" --algo bm -j DROP ")

    return s

def print_compress(res_list, num):
    count = 0
    record = {}
    for info in res_list:
        n = info.val
        c = info.cnt
        mx = len(info.val)
        end_pos = len(info.val) - 1
        s = ''
        for i in range(mx):
            a = n[end_pos - mx + i + 1]  # n是一个列表
            s += '%02x' % a  # 以十六进制的形式进行打印
        hex_str = str(s)
        if(len(hex_str) < num):
            record[hex_str] = record.get(hex_str,0) + c
        else:
            record[hex_str[0:num]] = record.get(hex_str[0:num], 0) + c
    file_name = pcap_list[0][0:-5] + '_' + str(int(num / 2)) + 'bytes' + '.txt'
    map_name = pcap_list[0][0:-5] + '_' + str(int(num / 2)) + 'bytes' +  '_feature_map' + '.txt'
    if len(record) > 0 :
        with open(file_name, 'w', encoding='utf-8') as f:
            ppp = sorted(record.items(), key=lambda d: d[1], reverse=True)
            for k,v in ppp:
                text = "iptables -I self_control  -m string --hex-string \"|" + k + "|\" --algo bm -j DROP "
                f.write(text + '\n')
                print(text)
                count += 1
        map = pd.DataFrame([[ i, record[i] ] for i in record.keys()])
        map.columns = ["val","cnt"]
        map=map.sort_values(by=["cnt"],ascending=False)
        map.to_csv(map_name,index=False)
        print("the number of rules is equal to %d" % count)
        res = (record, count)
        return res
    else:
        print("未发现有效重复特征值")
        return None


class feature_info:
    def __init__(self, val, cnt):
        self.val = val
        self.cnt = cnt                 # 一个只有属性的类

def feature_info_sort(info1, info2):
    return info1.cnt < info2.cnt       # 为使用

def feature_get(feature_set):
    from simhash import Simhash
    sim1 = Simhash('20485454502f312e310d0a4163636570743a202a2f2a0d0a43616368652d436f6e74726f6c3a206e')
    sim2 = Simhash('0d0a436f6e74656e742d')
    sim3 = Simhash('0d0a436f6e74656e742d547970653a206170706c69636174696f6e2f6f637465742d7374')
    sim4 = Simhash('0d0a416363657074')
    sim5 = Simhash('20485454502f312e310d0a557365722d4167656e743a2044616c76696b2f32')
    sim6 = Simhash('1603030028')   # 对特征值进行hash后于后面相似特征值的删除

    exclude_pattern = '(^17030300)|(^17030301)|(^17f10400)|(^16030100)|(^16030102)|(^14030300)'
    exclude_regex = re.compile(exclude_pattern)
    # exclude_regex.search(names[i]):


    shash_list = [sim1, sim2, sim3, sim4, sim5, sim6]

    print("\n========================= Feature =============================")

    feature_list = []
    res_list = []

    items = sorted(feature_set.items(), key=lambda a: a[1].cnt, reverse=True)  # 默认是升序, reverse指定降序
    # lambda的返回值是一个地址, 即是函数对象; sorted函数支持接受一个函数作为参数, 该参数作为sorted排序的依据
    for (key, info) in items:  # 对字典中的每一项特征打印输出
        if len(info.val) < 4:
            continue
        cnt = 0
        for v in info.val:
            if v != 0:
                cnt += 1       # 过滤掉为0的值;
        if cnt <= 2:
            continue           # 过滤掉0后如果太短了, 则去掉

        # print('feature count: ', info.cnt)   # 打印长度符合要求的项
        s = print_func(info.val, len(info.val), len(info.val) - 1)
        if info.cnt < 3 :
            continue
        if exclude_regex.match(s):
            continue
        for i in range(len(shash_list)):
            if shash_list[i].distance(Simhash(s)) < 22:       # 计算特征的海明距离, 如果相似度太高了就过滤掉
                break
            if i == len(shash_list) - 1:
                res_list.append(info)
        feature_list.append(info.val)
        #print('feature count: ', info.cnt)                   # 打印长度符合要求的项
    print('========================xxxxxxxxx===========================')
    for info in res_list:
        print("matched number is equal to ", info.cnt)
        print_func(info.val, len(info.val), len(info.val) - 1)
    print("===================final binary result is equal to ====================== ")
    # count = 0
    # for info in res_list:
    #     # print("matched number is equal to ", info.cnt)
          # print_func_binary(info.val, len(info.val), len(info.val) - 1)
    #     count += 1
    # print("the number of output rules is equal to % d" % count)
    # count = 0
    # pre_record = []
    # record = []
    # for info in res_list:
    #     n = info.val
    #     mx = len(info.val)
    #     end_pos = len(info.val) - 1
    #     s = ''
    #     for i in range(mx):
    #         a = n[end_pos - mx + i + 1]  # n是一个列表
    #         s += '%02x' % a  # 以十六进制的形式进行打印
    #     pre_record.append(str(s)[0:8])
    # for i in pre_record:
    #     if i not in record:
    #         record.append(i)
    # for i in record:
    #     print("iptables -I self_control  -m string --hex-string \" |" + i + "| \" --algo bm -j DROP ")
    #     count += 1
    # print("the number of rules is equal to %d" % count)
    #print("print res_list in feature_get")
    #for res in res_list:
    # print(res.val)
    # print_compress(res_list, 12)
    return res_list
def __flow_common(p, m, n, trie_tree, feature_set):                  # feature_set是一个字典
    mx, pos, mx_list, pos_list = lcs_func(m, n)                      # 调用了函数lcs_func, 这个函数返回四个值
    for i in range(len(mx_list)):
        mx = mx_list[i]
        pos = pos_list[i]
        if mx < 4:
            continue
        print('pos[0] is equal to ' + str(pos[0]))                    # 这里的pos是一个元组, pos[0]对应n
        print_func(n, mx, pos[0])                                     # 打印出两个包中相同的内容, pos是一个tuple
        if p == 0:                                                    # 这里的p是数据包的index
            for i in range(len(mx_list)):
                trie_tree.insert(n[pos[0] - mx + 1: pos[0] + 1])      # 把这个范围内的数据都插进去了(使用嵌套的字典实现了类似树的结构)
                #if len(pcap_list) == 1:
                if 1:
                    res = n[pos[0] - mx + 1: pos[0] + 1]
                    key = str(res)                                    # str将指定的值转化为字符串
                    if key in feature_set:
                        (feature_set[key]).cnt += 1                   # 字典里面存放着找到的相同值
                    else:
                        feature_set[key] = feature_info(res, 1)       # 初始化了一个类, 并赋给字典中的值
        else:
            res = trie_tree.get_common_start_with(n[pos[0] - mx + 1: pos[0] + 1])  # 传递了整个数组, 只传递到位置pos[0], 查看以往的记录有没有
            print('#combine:')
            print_func(res, len(res), len(res) - 1)

            key = str(res)                                            # str将指定值转化为字符串, 将res转化为字符串并作为key
            if key in feature_set:                                    # feature_set是一个字典, 判断是否已经存在了这个key
                (feature_set[key]).cnt += 1                           # 这里获取了字典里面的值, 若已存在, 则计数加 1
            else:
                feature_set[key] = feature_info(res, 1)  # __flow_common就获得了特征集合, 这里实例化了一个类, 并进行了初始化操作, 然后进行赋值
                                                                      # 字典的值是一个feature_info类
def get_common_from_diff_flow(pcap_list):
    analyzer = PcapAnalyzerManager(method='session', dropnum=0, time_smt=5, forbid443=False)  # 按照会话进行管理
    feature_set = {}
    trie_tree = Trie()                                            # 这里定义了一个类
    for p in range(len(pcap_list)):
        analyzer.clear()
        analyzer.append(pcap_list[p], 1)
        x, f_tuple = analyzer.binary(1024, True, True, True, True, multi_track=1, data_multiple=1, detail=True)
        # 这里给的数据是1024字节
        for u in range(0, len(x)):                                   # 这里的x是会话的集合
            if (len(x[u]) == 0):
                continue
            m = x[u][0]                                              # 传递了一个一维数组
            (y, z) = f_tuple[u]                                      # 会话的信息: 五元组 + 数据包的个数
            print('session ', u, ':')                                # 打印可以直接写参数
            print(socket.inet_ntop(socket.AF_INET, y[0]), ':', y[2], '<-->',
                  socket.inet_ntop(socket.AF_INET, y[1]), ':', y[3])
            print('num:', z)
            for v in range(u + 1, min(u + 100, len(x))):             # 这里限制了比较的流数不超过100条
                if (len(x[v]) == 0):
                    continue
                n = x[v][0]
                (y, z) = f_tuple[v]                                  # 获取会话的信息: 五元组 + 每条五元组中数据包的个数
                print('session ', u, ':')
                print(socket.inet_ntop(socket.AF_INET, y[0]), ':', y[2], '<-->',
                      socket.inet_ntop(socket.AF_INET, y[1]), ':', y[3])
                print('num:', z)                                     # 打印出会话中数据包的数目
                __flow_common(p, m, n, trie_tree, feature_set)       # p是pcap_list中的index
    return feature_set                                               # 从不同流中找特征
                                                                     # 这里只对每条会话中的第一条流进行比较

def get_common_from_same_flow(pcap_list, data_multiple=10):
    analyzer = PcapAnalyzerManager(method='session', dropnum=0, time_smt=5, forbid443=False)  # pcap文件解析所需的类
    feature_set = {}                                    # 这是一个字典
    # print(type(feature_set))
    trie_tree = Trie()
    for p in range(len(pcap_list)):                     # pcap_list存放的是pcap文件的路径
        analyzer.clear()
        analyzer.append(pcap_list[p], 1)                # 1 表示标签
        x, f_tuple = analyzer.binary(1024, True, True, True, True, multi_track=1, data_multiple=data_multiple, detail=True)
        #print("f_tuple is equal to")
        #print(f_tuple)
        # 这里获取的每个包的长度是1024字节的
        for u in range(len(x)):
            session = x[u]
            (y, z) = f_tuple[u]
            print('session ', u, ':')
            print(socket.inet_ntop(socket.AF_INET, y[0]), ':', y[2], '<-->',  # 打印IP + 端口
                  socket.inet_ntop(socket.AF_INET, y[1]), ':', y[3])
            print('num:', z)                                                  # 打印匹配到的数目
            for v in range(len(session)):
                for w in range(v + 1, len(session)):
                    m = session[v]
                    n = session[w]
                    __flow_common(p, m, n, trie_tree, feature_set)            # 寻找相同的字符串
                    trie_tree.clear_trees()
                                                                              # p是pcap列表中的计数

    return feature_set


if __name__ == '__main__':
    # pcap_list = ['./王者荣耀1.pcap','王者荣耀.pcap']
    pcap_list = ['./pcaps/PCAPdroid_24_2月_14_51_11.pcap']
    feature_set_same = get_common_from_same_flow(pcap_list)
    res_list_same = feature_get(feature_set_same)

    feature_set_diff = get_common_from_diff_flow(pcap_list)
    res_list_diff = feature_get(feature_set_diff)

    res_merge = res_list_same + res_list_diff

    feature_length = 8 # 修改特征位数 一般8位，10位，12位
    res_i = print_compress(res_merge, feature_length)
    if res_i:
        print("number of rules with limitions of 4 bytes is equal to %d" % res_i[1])
