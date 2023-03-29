import socket
import os, sys
import struct
from ctypes import *
import time
import datetime as dt
import tkinter as tk
import threading
from tkinter import messagebox

# 创建tkinter主窗口
window = tk.Tk()
window.title('嗅探工具：')
window.geometry('800x600')
# 本地监听
l = tk.Label(window, text='请您输入以太网卡ip：', width=50, height=3)
l.pack(side='top')
e = tk.Entry(window, show=None)
e.pack(side='top')
var = tk.StringVar()  # 定义一个字符串变量


# IP头定义
class IP(Structure):
    _fields_ = [
        ('ihl', c_ubyte, 4),
        ('version', c_ubyte, 4),
        ('tos', c_ubyte),
        ('len', c_ushort),
        ('id', c_ushort),
        ('offset', c_ushort),
        ('ttl', c_ubyte),
        ('protocol_num', c_ubyte),
        ('sum', c_ushort),
        ('src', c_ulong),
        ('dst', c_ulong),
        ("src_port", c_ushort),
        ("dst_port", c_ushort)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)  # 实例化类

    def __init__(self, socket_buffer=None):

        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}  # 创建一个字典，协议字段与协议名称对应
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        # inet_ntoa()函数将字节流转化为点分十进制的字符串，专用于IPv4地址转换
        # 将c_ulong类型的src(源地址)转为小端的long类型数据，返回源地址的字节流格式
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))
        # 协议判断
        try:
            self.protocol = self.protocol_map[self.protocol_num]  # 将协议号与协议名对应
        except:
            self.protocol = str(self.protocol_num)  # 若字典中没有，则直接输出协议号


# Windows下嗅探所有数据包，Linux下嗅探ICMP数据包
def strat():
    var = e.get()
    if os.name == "nt":  # 判断系统是否为window
        socket_protocol = socket.IPPROTO_IP  # 设置协议为ip协议
    else:
        socket_protocol = socket.IPPROTO_ICMP
    global sniffer

    # 创建一个原始套接字
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    try:

        sniffer.bind((var, 0))  # 套接字绑定地址，0默认所有端口
    except:
        tk.messagebox.showerror(title='错误', message='socket连接错误')  # 若绑定失败则弹窗解释

    # 设置ip头部
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # Windows下要打开混杂模式
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        # 设置开启混杂模式，socket.SIO_RCVALL默认接收所有数据，socket.RCVALL_ON开启
    show_th = threading.Thread(target=show)  # 创建一个线程，执行函数为show()
    show_th.setDaemon(True)
    show_th.start()


def show():
    window.title('抓包中')  # 更改界面标题
    while True:
        # 读取数据包
        raw_buffer = sniffer.recvfrom(65535)[0]  # 获取数据包，接收最大字节数为65565
        # 读取前20字节
        ip_header = IP(raw_buffer[0:24])
        # 输出协议和双方通信的IP地址
        now_time = dt.datetime.now().strftime('%T')  # 获取系统当前时间
        result = 'Protocol: ' + str(ip_header.protocol) + ' ' + str(ip_header.src_address) + ' : ' + str(
            ip_header.src_port) + ' -> ' + str(ip_header.dst_address) + ' : ' + str(
            ip_header.dst_port) + '  size:' + str(ip_header.len) + ' time:' + str(now_time) + '\n'  # 设置输出的字符串
        t.insert('end', result)  # 将每条输出插入到界面
        time.sleep(1)


def stop():
    window.title('已停止')
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)  # 关闭混杂模式，第一个参数是接收所有数据，第二个对应关闭
    sniffer.close()  # 关闭套接字


b_1 = tk.Button(window, text='确定', width=15, height=2, command=strat).pack(side='top')
t = tk.Text(window, width=100)
t.pack(side='top')
b_2 = tk.Button(window, text='停止', width=15, height=2, command=stop).pack()
window.mainloop()
