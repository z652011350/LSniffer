# LSniffer
国科大 2023 春季 网络攻防基础 实验1A
# 介绍
利用scapy实现抓包，tkinter实现gui\
对基本的协议过滤支持筛选 HTTP、TCP/UDP、IPv4/v6、ICMP 等不同类型、层次的数据包\
提供了网卡选择功能，可以进行实时抓取网卡上的数据包\
提供了IP+port的tcp流量追踪功能
# 使用说明
1. 选择网卡，默认全部网卡
2. 设置BPF过滤，默认不过滤
3. 点开始即可实时抓包 
4. 如需要查看某个包的详情，点’暂停’后，点击想要查看的包，在底部详情里便按协议层次划分，最下方的raw_data显示16进制数据
5. 如需要对IP+port进行tcp流量追踪，点’暂停’后，点击某个想要追踪的包，在点击追踪IP+port，即对已经抓取到了的包进行一次过滤，如还需要继续对该IP进行追踪点击’开始’即可，如不想追踪该ip了，点击停止，即重置
