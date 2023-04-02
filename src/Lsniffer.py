import tkinter
from tkinter import *
from tkinter import font, filedialog
from tkinter.constants import *
from tkinter.messagebox import askyesno
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Treeview
from tkinter.ttk import Combobox

from scapy.layers.inet import *
from scapy.layers.l2 import *
from scapy.all import *

import threading


class StatusBar(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self.label = Label(self, bd=1, relief=SUNKEN, anchor=W)
        self.label.pack(fill=X)

    def set(self, fmt, *args):
        self.label.config(text=fmt % args)
        self.label.update_idletasks()

    def clear(self):
        self.label.config(text="")
        self.label.update_idletasks()


def start_cap():
    global pause_flag, stop_flag, packet_list
    # 停止，重新开始抓包
    start_btn['state'] = DISABLED
    pause_btn['state'] = NORMAL
    stop_btn['state'] = NORMAL
    track_ip_port_btn['state'] = NORMAL
    track_pid_btn['state'] = NORMAL
    
    stop_flag = False
    if not pause_flag and not stop_flag:
        nif = select_nif.get()
        if nif == '全部网卡':
            nif = None

        # items = packet_list_tree.get_children()
        # for item in items:
        #     packet_list_tree.delete(item)
        # packet_list_tree.clipboard_clear()
        # global packet_id
        # packet_id = 1
        t = threading.Thread(target=cap_packet, args=(nif,))
        t.setDaemon(True)
        t.start()
        ##print('Thread')
    else:
        pause_flag = False


def cap_packet(nif=None):
    filters = fitler_entry.get()
    ##print(filters)


    stop_sending.clear()
    global packet_list
    # 清空列表
    packet_list.clear()
    #print('cap_packet')
    try:
        sniff(iface=nif, prn=(lambda x: process_packet(x)), filter=filters)
    except scapy.error.Scapy_Exception:
        tkinter.messagebox.askyesnocancel("错误", "过滤选项语法有误，请检查")
        start_btn['state'] = NORMAL
        pause_btn['state'] = DISABLED
        stop_btn['state'] = DISABLED
        track_ip_port_btn['state'] = DISABLED
        track_pid_btn['state'] = DISABLED


def process_packet(packet):
    global pause_flag, stop_flag
    if pause_flag == False and stop_flag == False:
        global packet_list
        sport = 'null'
        dport = 'null'
        pid = -1

        # return
        if packet.haslayer(IP):
            pid = packet[IP].id

        packet_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        if Ether in packet:
            src_ip = packet[Ether].src
            dst_ip = packet[Ether].dst
            proto_type = packet[Ether].type
            types = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x88cc: 'LLDP', 0x891D: 'TTE'}
            if proto_type in types:
                proto = types[proto_type]
            else:
                proto = 'LOOP'  # 协议
            # IP
            if proto == 'IPv4':

                protos = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6', 50: 'ESP',
                          89: 'OSPF'}
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                # sport = packet[IP].sport
                # dport = packet[IP].dport
                proto = packet[IP].proto
                ##print(proto)
                # if proto==2:
                    # return
                if proto in protos:
                    proto = protos[proto]
            # TCP
            if TCP in packet:
                protos_tcp = {80: 'Http', 443: 'Https', 23: 'Telnet', 21: 'Ftp', 20: 'ftp_data', 22: 'SSH', 25: 'SMTP'}
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                # 端口
                if sport in protos_tcp:
                    proto = protos_tcp[sport]
                elif dport in protos_tcp:
                    proto = protos_tcp[dport]
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                if packet[UDP].sport == 53 or packet[UDP].dport == 53:
                    proto = 'DNS'
        else:
            return

    

        length = len(packet)
        info = packet.summary()
        global packet_id,id_flag
        #print(id_flag)
        if id_flag == True:
            return
        # id_flag = False
        # #print('process_packet id_flag = true')

        # #print('process_packet')
        global track_tcp_ip_port_flag, track_tcp_pid_flag

        # return
        process_packet = [packet_id, packet_time, src_ip, dst_ip, proto, sport, dport, length, pid, info]
        if track_tcp_ip_port_flag:
            #print('track_tcp_ip_port_flag1')
            global track_src_ip, track_dst_ip, track_src_port, track_dst_port
            #print('track_tcp_ip_port_flag2')
            # return 
            if not check_is_save(process_packet, ip=[track_src_ip, track_dst_ip],
                                 port=[track_src_port, track_dst_port],
                                 flag = 0,cap_packet = packet):
                # id_flag = False
                #print('track_tcp_ip_port_flag3')
                return
            # #print('track_tcp_ip_port_flag4')
        elif track_tcp_pid_flag:
            global track_pid
            if not check_is_save(process_packet, pid=track_pid,
                                 flag = 0,cap_packet = packet):
                # id_flag = False
                return
        # #print('process_packet')
        id_flag = True
        packet_list.append({'packet': packet, 'process_packet': process_packet})
        # packet_id = packet_id + 1
        packet_tab_tree.insert("", 'end', packet_id, text=packet_id,
                                values=(packet_id, packet_time, src_ip, 
                                        dst_ip, proto, sport, dport, length, 
                                        pid, info))
        # packet_id = packet_id + 1
        packet_tab_tree.update_idletasks()
        packet_tab_tree.yview_moveto(1)
        packet_id = packet_id + 1


        # #print('process_packet id_flag = false')
        id_flag = False
    elif stop_flag == True:
            return threading.Thread.exit()


def show_detail_data(event):
    global selected_item
    selected_item = event.widget.selection()
    # 清空
    packet_data_tree.delete(*packet_data_tree.get_children())

    packet_data_tree.column('detail_data')
    # #print(selected_item)
    if selected_item == ():
        global packet_id,id_flag,stop_flag
        while id_flag == True:
            # #print('~~~~~show_detail_data id_flag~~~')
            pass
        id_flag = True
        # #print('show_detail_data id_flag = True')
        packet_id = 1
        id_flag = False
        # #print('show_detail_data id_flag = False')
        # 等待packlist的数据
        while packet_list == [] and stop_flag == False:
            pass
        if stop_flag == True: 
            return
        packet = packet_list[packet_id-1]['packet']
    else:
        local_id = int(selected_item[0]) - 1
        #print(local_id,len(packet_list))
        global pause_flag,track_tcp_pid_flag,track_tcp_ip_port_flag
        #print('stop_flag,pause_flag,track_tcp_pid_flag,track_tcp_ip_port_flag')
        #print(stop_flag,pause_flag,track_tcp_pid_flag,track_tcp_ip_port_flag)
        packet = packet_list[local_id]['packet']
    # # #print(packet_list[packet_id])

    lines = (packet.show(dump=True)).split('\n')
    last_tree_entry = None
    for line in lines:
        if line.startswith('#'):
            line = line.strip('# ')
            last_tree_entry = packet_data_tree.insert('', 'end', text=line)  # 第一个参数为空表示根节点
        else:
            packet_data_tree.insert(last_tree_entry, 'end', text=line)

    raw_data0 = hexdump(packet, dump=True)

    last_tree_entry = packet_data_tree.insert('', 'end', text='raw_data')
    for raw in raw_data0.split('\n'):
        packet_data_tree.insert(last_tree_entry, 'end', text=raw)
    


def pause_cap():
    start_btn['state'] = NORMAL
    pause_btn['state'] = DISABLED
    stop_btn['state'] = NORMAL
    track_ip_port_btn['state'] = NORMAL
    track_pid_btn['state'] = NORMAL
    global pause_flag
    pause_flag = True


def stop_cap():
    # 终止线程，停止抓包

    global track_tcp_ip_port_flag, track_tcp_pid_flag
    track_tcp_ip_port_flag = False
    track_tcp_pid_flag = False

    global packet_list, packet_id,id_flag

    global pause_flag, stop_flag
    pause_flag = False
    stop_flag = True
    stop_sending.set()
    while not stop_sending.is_set():
        # #print('~~~~~~~~~~~stop_sending~~~~~~~~')
        pass

    id_flag = True
    packet_id = 1
    id_flag = False

    packet_list.clear()

    # items = packet_list_tree.get_children()
    # for item in items:
    #     packet_list_tree.delete(item)
    # packet_list_tree.clipboard_clear()

    start_btn['state'] = NORMAL
    pause_btn['state'] = DISABLED
    stop_btn['state'] = NORMAL
    track_ip_port_btn['state'] = DISABLED
    track_pid_btn['state'] = DISABLED

    packet_list.clear()

    items = packet_tab_tree.get_children()
    # #print(items)
    for item in items:
        packet_tab_tree.delete(item)
    packet_tab_tree.clipboard_clear()


def track_tcp_ip_port():
    global track_tcp_ip_port_flag

    track_tcp_ip_port_flag = True


    local_packet_id = int(selected_item[0]) - 1
    selected_packet = packet_list[local_packet_id]['packet']
    processed_packet = packet_list[local_packet_id]['process_packet']

    # [packet_id, packet_time, src_ip, dst_ip, proto,
    #     0            1        2       3       4
    # sport, dport, length, pid, info]
    #   5      6      7      8     9

    # start_button['state'] = DISABLED
    # pause_button['state'] = NORMAL
    # track_proto = 'TCP'
    global track_src_ip,track_dst_ip,track_src_port,track_dst_port
    track_src_ip = processed_packet[2]
    track_dst_ip = processed_packet[3]
    track_src_port = processed_packet[5]
    track_dst_port = processed_packet[6]

    listOfEntriesInTreeView = packet_tab_tree.get_children()
    for each in listOfEntriesInTreeView:
        tmpEntriesInTreeView.append(packet_tab_tree.item(each))
        # #print(packet_list_tree.item(each)['values'])
        if not check_is_save(packet_tab_tree.item(each)['values'],
                             ip = [track_src_ip, track_dst_ip],
                             port= [track_src_port, track_dst_port],
                             flag = 0,cap_packet = selected_packet):
            packet_tab_tree.delete(each)
        else:
            print('~~~~~~~~~~~~~true~~~~~~~~~~~~~~')
            print(packet_tab_tree.item(each)['values'][2],packet_tab_tree.item(each)['values'][3])
            print([track_src_ip, track_dst_ip])
            print([track_src_port, track_dst_port])
            print('~~~~~~~~~~~~~true~~~~~~~~~~~~~~')
    
    packet_tab_tree.update_idletasks()


def track_tcp_pid():
    global track_tcp_pid_flag, track_pid
    track_tcp_pid_flag = True
    # # #print(local_packet_id)
    # #print(selected_item[0])
    local_packet_id = int(selected_item[0]) - 1
    selected_packet = packet_list[local_packet_id]['packet']
    processed_packet = packet_list[local_packet_id]['process_packet']

    track_pid = processed_packet[8]

    listOfEntriesInTreeView = packet_tab_tree.get_children()
    for each in listOfEntriesInTreeView:
        tmpEntriesInTreeView.append(packet_tab_tree.item(each))
        # #print(packet_list_tree.item(each)['values'])
        if not check_is_save(packet_tab_tree.item(each)['values'],
                            pid=track_pid,
                            flag = 0,cap_packet = selected_packet):
            packet_tab_tree.delete(each)

    packet_tab_tree.update_idletasks()

    # pass


def check_is_save(packet_info,
                  proto = '',src_ip='', dst_ip='',
                  src_port='', dst_port='',
                  pid='',flag = -1,cap_packet = '',ip=['',''],port=['','']):
    # #print(packet_info[4])
    # [packet_id, packet_time, src_ip, dst_ip, proto,
    #     0            1        2       3       4
    # sport, dport, length, pid, info]
    #   5      6      7      8     9
    if flag == 0:
        if TCP not in cap_packet:
           #print('not tcp')
           #print(cap_packet)
            return False
    if proto != '' and proto != packet_info[4]:
       #print(proto)
       #print(type(proto))
        return False
    if ip[0]!= '' and (packet_info[2] not in ip or packet_info[3] not in ip):
       #print('ip,packet_info[2],packet_info[3]')
       #print(ip,packet_info[2],packet_info[3])
        return False
    if ip[0]!= '' and packet_info[2] in ip and packet_info[3] in ip:
       print('~~~~~true_check_is_save~~~~~~~')
       print('true,ip,packet_info[2],packet_info[3]')
       print('packet_info[2] in ip',packet_info[2] in ip)
       print('packet_info[3] in ip',packet_info[3] in ip)
       print(ip,packet_info[2],packet_info[3])
       print('~~~~~~~~~~~~~~~')
        # return False
    if port[0]!='' and packet_info[5] not in port and packet_info[6] not in port:
       #print('port,packet_info[5],packet_info[6]')
       #print(port,packet_info[5],packet_info[6])
        return False
    if src_ip != '' and src_ip != packet_info[2]:
       #print('src_ip,packet_info[2]')
       #print(src_ip,packet_info[2])
        return False
    if dst_ip != '' and dst_ip != packet_info[3]:
       #print('dst_ip,packet_info[3]')
       #print(dst_ip,packet_info[3])
        return False
    if src_port != '' and src_port != packet_info[5]:
       #print('src_port,packet_info[5]')
       #print(src_port,packet_info[5])
        return False
    if dst_port != '' and dst_port != packet_info[6]:
       #print('dst_port,packet_info[6]')
       #print(dst_port,packet_info[6])

        return False
    if pid != '' and pid != packet_info[8]:
       #print('pid,packet_info[8]')
       #print(pid,packet_info[8])
        return False
    

    return True


tk = tkinter.Tk()
tk.title("垃圾嗅探器")

# 主窗体
main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5, orient=VERTICAL)

top_button_frame = Frame(tk)

# 顶部按钮

start_btn = Button(top_button_frame, width=8, text="开始", command=start_cap)
pause_btn = Button(top_button_frame, width=8, text="暂停", command=pause_cap)
stop_btn = Button(top_button_frame, width=8, text="停止", command=stop_cap)
track_ip_port_btn = Button(top_button_frame, width=8, text="追踪ip+port", command=track_tcp_ip_port)
track_pid_btn = Button(top_button_frame, width=8, text="追踪pid", command=track_tcp_pid)

start_btn['state'] = NORMAL
pause_btn['state'] = DISABLED
stop_btn['state'] = DISABLED
# track_ip_port_btn['state'] = DISABLED
# track_pid_btn['state'] = DISABLED



filter_label = Label(top_button_frame, width=10, text="BPF Filters :")
fitler_entry = Entry(top_button_frame)

select_nif = Combobox(top_button_frame, font='select', state="readonly")

select_nif['values'] = ['全部网卡'] + [nif.name for nif in get_working_ifaces() if nif.mac]
select_nif.current(0)

start_btn.pack(side=LEFT, padx=5)
pause_btn.pack(side=LEFT, after=start_btn, padx=5, pady=10)
stop_btn.pack(side=LEFT, after=pause_btn, padx=5, pady=10)
track_ip_port_btn.pack(side=LEFT, after=stop_btn, padx=5, pady=10)
track_pid_btn.pack(side=LEFT, after=track_ip_port_btn, padx=5, pady=10)
select_nif.pack(side=LEFT, after=track_pid_btn, padx=5, pady=10)
filter_label.pack(side=LEFT, after=select_nif, padx=0, pady=10)
fitler_entry.pack(side=LEFT, after=filter_label, padx=5, pady=10, fill=X, expand=YES)

top_button_frame.pack(side=TOP, fill=X)

packet_tab_frame = Frame()
packet_tab_sub_frame = Frame(packet_tab_frame)
packet_tab_tree = Treeview(packet_tab_sub_frame, selectmode='browse')  # 选择数据表

packet_tab_tree.bind('<<TreeviewSelect>>', show_detail_data)

packet_tab_vscrollbar = Scrollbar(packet_tab_sub_frame, orient="vertical", command=packet_tab_tree.yview)
packet_tab_vscrollbar.pack(side=RIGHT, fill=Y, expand=YES)
packet_tab_tree.configure(yscrollcommand=packet_tab_vscrollbar.set)
packet_tab_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)

packet_tab_hscrollbar = Scrollbar(packet_tab_frame, orient="horizontal", command=packet_tab_tree.xview)
packet_tab_hscrollbar.pack(side=BOTTOM, fill=X, expand=YES)
packet_tab_tree.configure(xscrollcommand=packet_tab_hscrollbar.set)

packet_tab_tree["columns"] = (
    "ID", "Time", "Src ip", "Dst ip", "Protocol", "Src port", "Dst port", "Length", "pid", "Info")
packet_tab_column_width = [30, 110, 140, 140, 80, 60, 60, 80, 50, 450]
packet_tab_tree['show'] = 'headings'
for column_name, column_width in zip(packet_tab_tree["columns"], packet_tab_column_width):
    packet_tab_tree.column(column_name, width=column_width, anchor='w')
    packet_tab_tree.heading(column_name, text=column_name)
packet_tab_tree.pack(side=LEFT, fill=X, expand=YES)
packet_tab_frame.pack(side=TOP, fill=X, padx=5, pady=5, expand=YES, anchor='n')

main_panedwindow.add(packet_tab_frame)

# 数据区
packet_data_frame = Frame()
packet_data_sub_frame = Frame(packet_data_frame)
packet_data_tree = Treeview(packet_data_sub_frame, selectmode='browse')
packet_data_tree["columns"] = ("detail_data",)
packet_data_tree.column('detail_data', anchor='w')
packet_data_tree.heading('#0', text='数据表解析', anchor='w')
packet_data_tree.pack(side=LEFT, fill=X, expand=YES)

packet_data_vscrollbar = Scrollbar(packet_data_sub_frame, orient="vertical", command=packet_data_tree.yview)
packet_data_vscrollbar.pack(side=RIGHT, fill=Y)
packet_data_tree.configure(yscrollcommand=packet_data_vscrollbar.set)
packet_data_sub_frame.pack(side=TOP, fill=X, expand=YES)

packet_data_hscrollbar = Scrollbar(packet_data_frame, orient="horizontal", command=packet_data_tree.xview)
packet_data_hscrollbar.pack(side=BOTTOM, fill=X)
packet_data_tree.configure(xscrollcommand=packet_data_hscrollbar.set)
packet_data_frame.pack(side=LEFT, fill=X, padx=5, pady=5, expand=YES)

main_panedwindow.add(packet_data_frame)

main_panedwindow.pack(fill=BOTH, expand=1)

status_bar = StatusBar(tk)
status_bar.pack(side=BOTTOM, fill=X)

stop_sending = threading.Event()

packet_id = 1
id_flag = False

packet_list = []

pause_flag = False

stop_flag = False

selected_item = None

track_tcp_ip_port_flag = False
track_tcp_pid_flag = False

track_proto = None
track_src_ip = None
track_dst_ip = None
track_src_port = None
track_dst_port = None
track_pid = None

tmpEntriesInTreeView = []

tk.mainloop()
