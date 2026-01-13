# main.py
import tkinter as tk
from tkinter import ttk, messagebox, Menu
import subprocess
import threading
import socket
import re
import time

# ======================
# 获取 ARP 表（用于 MAC 地址）
# ======================
def get_arp_table():
    """返回 {ip: mac} 字典"""
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        arp_lines = result.stdout.splitlines()
        arp_dict = {}
        for line in arp_lines:
            # 匹配 IP 和 MAC（Windows 格式）
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9\-:]{12,})', line)
            if match:
                ip = match.group(1)
                mac = match.group(2).replace('-', ':').upper()
                arp_dict[ip] = mac
        return arp_dict
    except:
        return {}

# ======================
# Ping 单个主机
# ======================
def ping_host(ip, timeout_ms=1000):
    try:
        result = subprocess.run(
            ['ping', '-n', '1', '-w', str(timeout_ms), ip],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if "TTL=" in result.stdout:
            # 提取响应时间
            time_match = re.search(r'time[=<](\d+)ms', result.stdout)
            rtt = time_match.group(1) + "ms" if time_match else "N/A"
            return True, rtt
        else:
            return False, ""
    except Exception as e:
        return False, ""

# ======================
# Tracert 功能
# ======================
def tracert_host(ip):
    try:
        result = subprocess.run(
            ['tracert', '-h', '20', '-w', '1000', ip],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return result.stdout if result.returncode == 0 else "Tracert 失败"
    except Exception as e:
        return f"错误: {e}"

# ======================
# 获取主机名
# ======================
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ""

# ======================
# GUI 主程序
# ======================
class QuickPingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("QuickPing Pro - 局域网扫描工具")
        self.root.geometry("950x650")
        self.scanning = False
        self.arp_cache = {}

        self.create_widgets()

    def create_widgets(self):
        # === 控制栏 ===
        control_frame = tk.Frame(self.root)
        control_frame.pack(pady=5, fill=tk.X, padx=10)

        tk.Label(control_frame, text="IP段:").pack(side=tk.LEFT, padx=5)
        self.ip_base_var = tk.StringVar(value="192.168.1")
        tk.Entry(control_frame, textvariable=self.ip_base_var, width=15).pack(side=tk.LEFT, padx=5)

        tk.Label(control_frame, text="从").pack(side=tk.LEFT, padx=5)
        self.start_var = tk.StringVar(value="1")
        tk.Entry(control_frame, textvariable=self.start_var, width=5).pack(side=tk.LEFT, padx=5)

        tk.Label(control_frame, text="到").pack(side=tk.LEFT, padx=5)
        self.end_var = tk.StringVar(value="30")
        tk.Entry(control_frame, textvariable=self.end_var, width=5).pack(side=tk.LEFT, padx=5)

        tk.Label(control_frame, text="超时(ms):").pack(side=tk.LEFT, padx=5)
        self.timeout_var = tk.StringVar(value="1000")
        tk.Entry(control_frame, textvariable=self.timeout_var, width=6).pack(side=tk.LEFT, padx=5)

        btn_frame = tk.Frame(control_frame)
        btn_frame.pack(side=tk.RIGHT)

        self.btn_start = tk.Button(btn_frame, text="开始扫描", command=self.start_scan, bg="#4CAF50", fg="white")
        self.btn_start.pack(side=tk.LEFT, padx=5)

        self.btn_stop = tk.Button(btn_frame, text="停止", command=self.stop_scan, state=tk.DISABLED, bg="#f44336", fg="white")
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        self.btn_save = tk.Button(btn_frame, text="保存结果", command=self.save_results)
        self.btn_save.pack(side=tk.LEFT, padx=5)

        self.btn_close = tk.Button(btn_frame, text="退出", command=self.root.quit)
        self.btn_close.pack(side=tk.LEFT, padx=5)

        # === 结果表格 ===
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        columns = ("IP地址", "MAC地址", "主机名", "状态", "响应时间")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150, anchor=tk.CENTER)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        # === 右键菜单（用于 Tracert）===
        self.context_menu = Menu(self.tree, tearoff=0)
        self.context_menu.add_command(label="Tracert 路由跟踪", command=self.do_tracert)
        self.tree.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def do_tracert(self):
        selected = self.tree.focus()
        if not selected:
            messagebox.showwarning("提示", "请先选择一个 IP 地址")
            return
        ip = self.tree.item(selected)['values'][0]
        if not ip or ip == "":
            return

        # 弹出新窗口显示 Tracert 结果
        tracert_win = tk.Toplevel(self.root)
        tracert_win.title(f"Tracert - {ip}")
        tracert_win.geometry("700x500")

        text = tk.Text(tracert_win, wrap=tk.NONE)
        vsb = tk.Scrollbar(tracert_win, orient="vertical", command=text.yview)
        hsb = tk.Scrollbar(tracert_win, orient="horizontal", command=text.xview)
        text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        # 在线程中执行 Tracert（避免卡死）
        def run_tracert():
            text.insert(tk.END, f"正在执行 tracert {ip} ...\n")
            text.update_idletasks()
            output = tracert_host(ip)
            text.delete(1.0, tk.END)
            text.insert(tk.END, output)

        threading.Thread(target=run_tracert, daemon=True).start()

    def start_scan(self):
        if self.scanning:
            return

        try:
            start = int(self.start_var.get())
            end = int(self.end_var.get())
            timeout = int(self.timeout_var.get())
            ip_base = self.ip_base_var.get().strip()
            if not ip_base:
                raise ValueError("IP段不能为空")
        except ValueError as e:
            messagebox.showerror("输入错误", f"请检查输入：{e}")
            return

        if start < 0 or end > 255 or start > end:
            messagebox.showerror("范围错误", "IP范围应在 0～255 之间")
            return

        # 清空旧结果 & 刷新 ARP 表
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.arp_cache = get_arp_table()  # 预加载 ARP 表

        self.scanning = True
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)

        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(ip_base, start, end, timeout),
            daemon=True
        )
        self.scan_thread.start()

    def _scan_worker(self, ip_base, start, end, timeout):
        for i in range(start, end + 1):
            if not self.scanning:
                break
            ip = f"{ip_base}.{i}"
            is_alive, rtt = ping_host(ip, timeout)
            if is_alive:
                hostname = get_hostname(ip)
                mac = self.arp_cache.get(ip, "N/A")
                self.tree.insert("", "end", values=(ip, mac, hostname, "✅ 在线", rtt))
            else:
                self.tree.insert("", "end", values=(ip, "N/A", "", "❌ 离线", ""))

            self.root.after(10, lambda: None)

        self.root.after(0, self._scan_finished)

    def _scan_finished(self):
        self.scanning = False
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        messagebox.showinfo("完成", "扫描已完成！")

    def stop_scan(self):
        self.scanning = False
        self.btn_stop.config(state=tk.DISABLED)

    def save_results(self):
        items = self.tree.get_children()
        if not items:
            messagebox.showwarning("提示", "没有结果可保存")
            return

        with open("ping_result.txt", "w", encoding="utf-8") as f:
            f.write("IP地址\tMAC地址\t主机名\t状态\t响应时间\n")
            for item in items:
                values = self.tree.item(item)['values']
                f.write(f"{values[0]}\t{values[1]}\t{values[2]}\t{values[3]}\t{values[4]}\n")

        messagebox.showinfo("成功", "结果已保存到 ping_result.txt")

# ======================
# 入口
# ======================
if __name__ == "__main__":
    root = tk.Tk()
    app = QuickPingApp(root)
    root.mainloop()