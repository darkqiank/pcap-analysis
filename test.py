from pcapreader import PcapReader

p=PcapReader('pcaps/PCAPdroid_24_2月_14_51_11.pcap')
p.split_by_time(1.0)
print(p.len())