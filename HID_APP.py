import tkinter as tk
from tkinter import ttk, messagebox
import usb.core
import usb.util
import time

class HIDTesterApp:
    def __init__(self, master):
        self.master = master
        master.title("USB HID Decoder & Tester (PyUSB)")
        master.geometry("950x850")

        self.device = None
        self.active_interface = None
        self.ep_in = None
        self.ep_out = None
        self.reading_status = False

        # --- UI Layout ---
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(pady=10, padx=10, fill="both", expand=True)

        self.tab_connect = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_connect, text="1. Decode & Interface")
        self._setup_connect_tab(self.tab_connect)

        self.tab_test = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_test, text="2. Report Test")
        self.notebook.tab(self.tab_test, state='disabled') 
        self._setup_test_tab(self.tab_test)
        
        master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _setup_connect_tab(self, tab):
        frame_top = ttk.Frame(tab)
        frame_top.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(frame_top, text="VID:").pack(side="left")
        self.vid_entry = ttk.Entry(frame_top, width=8); self.vid_entry.insert(0, "0d62")
        self.vid_entry.pack(side="left", padx=5)

        ttk.Label(frame_top, text="PID:").pack(side="left")
        self.pid_entry = ttk.Entry(frame_top, width=8); self.pid_entry.insert(0, "3748")
        self.pid_entry.pack(side="left", padx=5)

        ttk.Button(frame_top, text="Query Device", command=self.enumerate_devices).pack(side="left", padx=10)
        
        frame_mid = ttk.LabelFrame(tab, text="Select Interface")
        frame_mid.pack(fill="x", padx=10, pady=5)
        
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(frame_mid, textvariable=self.interface_var, state="readonly")
        self.interface_dropdown.pack(side="left", padx=5, pady=10, fill="x", expand=True)
        self.interface_dropdown.bind("<<ComboboxSelected>>", self.display_interface_details)
        
        ttk.Button(frame_mid, text="Claim Interface", command=self.open_device).pack(side="left", padx=10)

        self.detail_text = tk.Text(tab, height=25, background="#121212", foreground="#00FF41", font=("Courier New", 10))
        self.detail_text.pack(fill="both", expand=True, padx=10, pady=5)

    def send_sequence(self, commands):
        """Generic function to send a list of commands with 1s delay."""
        def execute_step(index):
            if index < len(commands):
                self.out_entry.delete(0, tk.END)
                self.out_entry.insert(0, commands[index])
                self.send_output_report()
                # Schedule next step
                self.master.after(2000, lambda: execute_step(index + 1))
        execute_step(0)

    def _setup_test_tab(self, tab):
        frame_io = ttk.Frame(tab)
        frame_io.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Corrected variable name: self.out_f
        self.out_f = ttk.LabelFrame(frame_io, text="Output Report")
        self.out_f.pack(fill="x", pady=5)
        
        ttk.Label(self.out_f, text="Report ID (Hex):").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.rid_entry = ttk.Entry(self.out_f, width=10)
        self.rid_entry.insert(0, "20")
        self.rid_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        ttk.Label(self.out_f, text="Data (Hex, spaces optional):").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.out_entry = ttk.Entry(self.out_f, width=50)
        self.out_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Button(self.out_f, text="Send Report", command=self.send_output_report).grid(row=1, column=2, padx=10, pady=5)
        self.out_f.columnconfigure(1, weight=1)
        
        # Sequence Buttons
        cmd_823 = ["E1 01 03", "10 01 05 10", "E1 01 02 F4 00"]
        ttk.Button(self.out_f, text="Set Motor Angle 82.3", 
                   command=lambda: self.send_sequence(cmd_823)).grid(row=2, column=0, padx=10, pady=5)
                   
        cmd_15 = ["E1 01 03", "10 01 07 FD", "E1 01 02 0F 90"]
        ttk.Button(self.out_f, text="Set Motor Angle 15", 
                   command=lambda: self.send_sequence(cmd_15)).grid(row=2, column=1, padx=10, pady=5)
                   
        ttk.Button(self.out_f, text="Get Motor Position", 
                   command=lambda: [self.out_entry.delete(0,tk.END), self.out_entry.insert(0,"11 01")]).grid(row=3, column=0, padx=10, pady=5)
                   
        cmd_fan = ["F1 01 20", "F1 01 40 32"]
        ttk.Button(self.out_f, text="Fab on", 
                   command=lambda: self.send_sequence(cmd_fan)).grid(row=3, column=1, padx=10, pady=5)
        
        # Input Section
        in_f = ttk.LabelFrame(frame_io, text="Input Monitor")
        in_f.pack(fill="both", expand=True, pady=5)
        
        monitor_btn_frame = ttk.Frame(in_f)
        monitor_btn_frame.pack(fill="x")
        ttk.Button(monitor_btn_frame, text="Start Monitor", command=self.start_reading).pack(side="left", padx=5, pady=2)
        ttk.Button(monitor_btn_frame, text="Stop Monitor", command=self.stop_reading).pack(side="left", padx=5, pady=2)
        ttk.Button(monitor_btn_frame, text="Clear", command=lambda: self.monitor_text.delete('1.0', tk.END)).pack(side="left", padx=5, pady=2)
        
        self.monitor_text = tk.Text(in_f, height=15, background="#f0f0f0")
        self.monitor_text.pack(fill="both", expand=True, padx=5, pady=5)

    def decode_hid_descriptor(self, data):
        results = []
        report_ids = []
        usage_page = "Unknown"
        i = 0
        while i < len(data):
            b = data[i]
            size = b & 0x03
            if size == 3: size = 4
            tag = (b & 0xFC) >> 2
            val = 0
            for j in range(size):
                if i + 1 + j < len(data):
                    val |= (data[i + 1 + j] << (8 * j))
            if tag == 0x01: usage_page = f"0x{val:04X}"
            elif tag == 0x21: report_ids.append(val)
            elif tag == 0x02: results.append(f"Usage: 0x{val:04X} (Page: {usage_page})")
            i += 1 + size
        return sorted(list(set(report_ids))), results

    def enumerate_devices(self):
        try:
            vid = int(self.vid_entry.get(), 16)
            pid = int(self.pid_entry.get(), 16)
            self.device = usb.core.find(idVendor=vid, idProduct=pid)
            if not self.device:
                messagebox.showerror("Error", "Device not found.")
                return
            intfs = [f"Interface {intf.bInterfaceNumber}" for cfg in self.device for intf in cfg]
            self.interface_dropdown['values'] = intfs
            if intfs: 
                self.interface_dropdown.current(0)
                self.display_interface_details()
        except Exception as e: 
            messagebox.showerror("Error", f"Enumeration failed: {e}")

    def display_interface_details(self, event=None):
        if not self.device: return
        intf_id = int(self.interface_var.get().split(' ')[1])
        try:
            raw_desc = self.device.ctrl_transfer(0x81, 0x06, 0x2200, intf_id, 512)
            report_ids, usages = self.decode_hid_descriptor(raw_desc)
        except Exception as e:
            report_ids, usages = [], [f"Query failed: {e}"]

        cfg = self.device.get_active_configuration()
        intf = cfg[(intf_id, 0)]
        info = [
            f">> HARDWARE DECODE: INTERFACE {intf_id}",
            f"Manufacturer: {usb.util.get_string(self.device, self.device.iManufacturer)}",
            f"Product:      {usb.util.get_string(self.device, self.device.iProduct)}",
            f"HID Report IDs Found: {', '.join([hex(x) for x in report_ids]) if report_ids else '0x00 (Single Report)'}",
            "-"*60,
            "HID STRUCTURE DETAILS:"
        ] + usages + ["-"*60]
        for ep in intf:
            dir_str = "IN" if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN else "OUT"
            info.append(f"Endpoint {hex(ep.bEndpointAddress)}: {dir_str} | MaxPkt: {ep.wMaxPacketSize} | Interval: {ep.bInterval}ms")
        self.detail_text.delete('1.0', tk.END)
        self.detail_text.insert(tk.END, "\n".join(info))

    def open_device(self):
        try:
            intf_id = int(self.interface_var.get().split(' ')[1])
            if self.device.is_kernel_driver_active(intf_id):
                self.device.detach_kernel_driver(intf_id)
            usb.util.claim_interface(self.device, intf_id)
            self.active_interface = intf_id
            cfg = self.device.get_active_configuration()
            intf = cfg[(intf_id, 0)]
            self.ep_in = usb.util.find_descriptor(intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN)
            self.ep_out = usb.util.find_descriptor(intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT)
            self.notebook.tab(self.tab_test, state='normal')
            self.notebook.select(self.tab_test)
            messagebox.showinfo("Success", f"Interface {intf_id} Claimed.")
        except Exception as e: 
            messagebox.showerror("Error", f"Claim failed: {e}")

    def send_output_report(self):
        try:
            rid = int(self.rid_entry.get(), 16)
            data_str = self.out_entry.get().replace(" ", "")
            data = [int(data_str[i:i+2], 16) for i in range(0, len(data_str), 2)]
            buf = [rid] + data
            if self.ep_out:
                self.ep_out.write(buf)
            else:
                self.device.ctrl_transfer(0x21, 0x09, (0x02 << 8) | rid, self.active_interface, buf)
            self.monitor_text.insert(tk.END, f"[SENT] ID:{hex(rid)} Data:{' '.join([f'{b:02X}' for b in data])}\n")
            self.monitor_text.see(tk.END)
        except Exception as e: 
            messagebox.showerror("Write Error", str(e))

    def start_reading(self):
        if not self.ep_in:
            messagebox.showwarning("Warning", "No IN endpoint available.")
            return
        self.reading_status = True
        self._read_loop()

    def _read_loop(self):
        if not self.reading_status or not self.device: return
        try:
            data = self.device.read(self.ep_in.bEndpointAddress, self.ep_in.wMaxPacketSize, timeout=20)
            if data:
                self.monitor_text.insert(tk.END, f"[RECV] {' '.join([f'{b:02X}' for b in data])}\n")
                self.monitor_text.see(tk.END)
        except usb.core.USBError:
            pass 
        self.master.after(10, self._read_loop)

    def stop_reading(self):
        self.reading_status = False

    def on_closing(self):
        if self.device and self.active_interface is not None:
            try:
                usb.util.release_interface(self.device, self.active_interface)
            except: pass
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = HIDTesterApp(root)
    root.mainloop()
