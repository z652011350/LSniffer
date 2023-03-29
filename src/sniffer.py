import socket
from scapy.all import *

# 创建原始套接字，以便从网络接口读取数据包
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

# 开始无限循环，嗅探网络接口上的所有数据包
while True:
    # 从原始套接字读取数据包
    packet, addr = s.recvfrom(65535)

    # 解析数据包，提取所需信息
    packet = Ether(packet)
    if IP in packet:
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        protocol = ip.proto
        if protocol == 6 and TCP in packet:
            tcp = packet[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            # 可以在这里追踪TCP流

    # 显示数据包信息
    print("src_ip:", src_ip, "dst_ip:", dst_ip, "protocol:", protocol, "src_port:", src_port, "dst_port:", dst_port)
