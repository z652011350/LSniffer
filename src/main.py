import tkinter as tk

def start_sniffer():
    # 嗅探
    pass

def stop_sniffer():
    # 停止嗅探
    pass


root = tk.Tk()
root.title("网络嗅探器")

start_button = tk.Button(root, text="开始嗅探", command=start_sniffer)
start_button.pack()

data_window = tk.Toplevel(root)
data_window.title("已捕获数据包")

data_box = tk.Text(data_window, height=20, width=50)
data_box.pack()

stop_button = tk.Button(root, text="停止嗅探", command=stop_sniffer)
stop_button.pack()

text_box = tk.Text(root, height=20, width=50)
text_box.pack()

root.mainloop()
