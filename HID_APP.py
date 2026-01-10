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
        self.monitor_text2 = None
        
        # Vars for processed data on tab 3
        self.voltage_var = tk.StringVar(value="N/A")
        self.fan_duty_var = tk.StringVar(value="N/A")
        self.temperature_var = tk.StringVar(value="N/A")

        # Embed the temperature table directly into the code
        self.temp_table = [
            {'temp': 0, 'max': 188, 'min': 186}, {'temp': 1, 'max': 186, 'min': 184},
            {'temp': 2, 'max': 184, 'min': 182}, {'temp': 3, 'max': 182, 'min': 180},
            {'temp': 4, 'max': 179, 'min': 177}, {'temp': 5, 'max': 177, 'min': 175},
            {'temp': 6, 'max': 175, 'min': 173}, {'temp': 7, 'max': 172, 'min': 170},
            {'temp': 8, 'max': 170, 'min': 168}, {'temp': 9, 'max': 168, 'min': 166},
            {'temp': 10, 'max': 165, 'min': 163}, {'temp': 11, 'max': 163, 'min': 161},
            {'temp': 12, 'max': 160, 'min': 158}, {'temp': 13, 'max': 158, 'min': 156},
            {'temp': 14, 'max': 155, 'min': 154}, {'temp': 15, 'max': 153, 'min': 151},
            {'temp': 16, 'max': 150, 'min': 149}, {'temp': 17, 'max': 148, 'min': 146},
            {'temp': 18, 'max': 145, 'min': 144}, {'temp': 19, 'max': 143, 'min': 141},
            {'temp': 20, 'max': 140, 'min': 139}, {'temp': 21, 'max': 138, 'min': 137},
            {'temp': 22, 'max': 136, 'min': 134}, {'temp': 23, 'max': 133, 'min': 132},
            {'temp': 24, 'max': 131, 'min': 129}, {'temp': 25, 'max': 128, 'min': 127},
            {'temp': 26, 'max': 126, 'min': 124}, {'temp': 27, 'max': 123, 'min': 122},
            {'temp': 28, 'max': 121, 'min': 120}, {'temp': 29, 'max': 119, 'min': 117},
            {'temp': 30, 'max': 116, 'min': 115}, {'temp': 31, 'max': 114, 'min': 113},
            {'temp': 32, 'max': 112, 'min': 110}, {'temp': 33, 'max': 110, 'min': 108},
            {'temp': 34, 'max': 107, 'min': 106}, {'temp': 35, 'max': 105, 'min': 103},
            {'temp': 36, 'max': 103, 'min': 101}, {'temp': 37, 'max': 101, 'min': 99},
            {'temp': 38, 'max': 99, 'min': 97}, {'temp': 39, 'max': 97, 'min': 95},
            {'temp': 40, 'max': 95, 'min': 93}, {'temp': 41, 'max': 93, 'min': 91},
            {'temp': 42, 'max': 91, 'min': 89}, {'temp': 43, 'max': 89, 'min': 87},
            {'temp': 44, 'max': 87, 'min': 85}, {'temp': 45, 'max': 85, 'min': 83},
            {'temp': 46, 'max': 83, 'min': 81}, {'temp': 47, 'max': 81, 'min': 79},
            {'temp': 48, 'max': 79, 'min': 77}, {'temp': 49, 'max': 78, 'min': 76},
            {'temp': 50, 'max': 76, 'min': 74}, {'temp': 51, 'max': 74, 'min': 72},
            {'temp': 52, 'max': 72, 'min': 70}, {'temp': 53, 'max': 71, 'min': 69},
            {'temp': 54, 'max': 69, 'min': 67}, {'temp': 55, 'max': 68, 'min': 66},
            {'temp': 56, 'max': 66, 'min': 64}, {'temp': 57, 'max': 65, 'min': 63},
            {'temp': 58, 'max': 63, 'min': 61}, {'temp': 59, 'max': 62, 'min': 60},
            {'temp': 60, 'max': 60, 'min': 58}, {'temp': 61, 'max': 59, 'min': 57},
            {'temp': 62, 'max': 57, 'min': 55}, {'temp': 63, 'max': 56, 'min': 54},
            {'temp': 64, 'max': 55, 'min': 53}, {'temp': 65, 'max': 53, 'min': 51},
            {'temp': 66, 'max': 52, 'min': 50}, {'temp': 67, 'max': 51, 'min': 49},
            {'temp': 68, 'max': 50, 'min': 48}, {'temp': 69, 'max': 49, 'min': 47},
            {'temp': 70, 'max': 47, 'min': 46}, {'temp': 71, 'max': 46, 'min': 44},
            {'temp': 72, 'max': 45, 'min': 43}, {'temp': 73, 'max': 44, 'min': 42},
            {'temp': 74, 'max': 43, 'min': 41}, {'temp': 75, 'max': 42, 'min': 40},
            {'temp': 76, 'max': 41, 'min': 39}, {'temp': 77, 'max': 40, 'min': 38},
            {'temp': 78, 'max': 39, 'min': 37}, {'temp': 79, 'max': 38, 'min': 36},
            {'temp': 80, 'max': 37, 'min': 36}, {'temp': 81, 'max': 36, 'min': 35},
            {'temp': 82, 'max': 36, 'min': 34}, {'temp': 83, 'max': 35, 'min': 33},
            {'temp': 84, 'max': 34, 'min': 32}, {'temp': 85, 'max': 33, 'min': 32},
            {'temp': 86, 'max': 32, 'min': 31}, {'temp': 87, 'max': 32, 'min': 30},
            {'temp': 88, 'max': 31, 'min': 29}, {'temp': 89, 'max': 30, 'min': 29},
            {'temp': 90, 'max': 29, 'min': 28}, {'temp': 91, 'max': 29, 'min': 27},
            {'temp': 92, 'max': 28, 'min': 27}, {'temp': 93, 'max': 27, 'min': 26},
            {'temp': 94, 'max': 27, 'min': 25}, {'temp': 95, 'max': 26, 'min': 25},
            {'temp': 96, 'max': 26, 'min': 24}, {'temp': 97, 'max': 25, 'min': 24},
            {'temp': 98, 'max': 24, 'min': 23}, {'temp': 99, 'max': 24, 'min': 22},
            {'temp': 100, 'max': 23, 'min': 22}
        ]

        # --- UI Layout ---
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(pady=10, padx=10, fill="both", expand=True)

        self.tab_connect = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_connect, text="1. Decode & Interface")
        self._setup_connect_tab(self.tab_connect)

        self.tab_test = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_test, text="2. Report Test")
        self._setup_test_tab(self.tab_test)

        self.tab_test2 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_test2, text="3. Report Test 2")
        self._setup_test_tab2(self.tab_test2)

        self.notebook.tab(self.tab_test, state='disabled') 
        self.notebook.tab(self.tab_test2, state='disabled') 
        
        master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _get_temp_from_adc(self, adc_value):
        for entry in self.temp_table:
            if entry['min'] <= adc_value <= entry['max']:
                return entry['temp']
        return "N/A"

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

    def _setup_test_tab2(self, tab):
        frame_io = ttk.Frame(tab)
        frame_io.pack(fill="both", expand=True, padx=10, pady=10)
        
        # --- Top part for sending reports ---
        self.out_f2 = ttk.LabelFrame(frame_io, text="Output Report")
        self.out_f2.pack(fill="x", pady=5)
        
        ttk.Label(self.out_f2, text="Report ID (Hex):").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.rid_entry2 = ttk.Entry(self.out_f2, width=10)
        self.rid_entry2.insert(0, "20")
        self.rid_entry2.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        ttk.Label(self.out_f2, text="Data (Hex, spaces optional):").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.out_entry2 = ttk.Entry(self.out_f2, width=50)
        self.out_entry2.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Button(self.out_f2, text="Send Report", command=self.send_output_report2).grid(row=1, column=2, padx=10, pady=5)
        self.out_f2.columnconfigure(1, weight=1)
        
        cmd_823 = ["E1 01 03", "10 01 05 10", "E1 01 02 F4 00"]
        ttk.Button(self.out_f2, text="Set Motor Angle 82.3", command=lambda: self.send_sequence2(cmd_823)).grid(row=2, column=0, padx=10, pady=5)
        cmd_15 = ["E1 01 03", "10 01 07 FD", "E1 01 02 0F 90"]
        ttk.Button(self.out_f2, text="Set Motor Angle 15", command=lambda: self.send_sequence2(cmd_15)).grid(row=2, column=1, padx=10, pady=5)
        ttk.Button(self.out_f2, text="Get Motor Position", command=lambda: [self.out_entry2.delete(0,tk.END), self.out_entry2.insert(0,"11 01")]).grid(row=3, column=0, padx=10, pady=5)
        cmd_fan = ["F1 01 20", "F1 01 40 32"]
        ttk.Button(self.out_f2, text="Fab on", command=lambda: self.send_sequence2(cmd_fan)).grid(row=3, column=1, padx=10, pady=5)
        
        ttk.Button(self.out_f2, text="Get Temp", 
                   command=lambda: [self.out_entry2.delete(0,tk.END), self.out_entry2.insert(0,"F1 01 10")]).grid(row=4, column=0, padx=10, pady=5)

        # --- Middle part for processed data ---
        proc_f = ttk.LabelFrame(frame_io, text="Processed Data")
        proc_f.pack(fill="x", pady=(10, 5))
        
        ttk.Label(proc_f, text="Voltage:").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        ttk.Label(proc_f, textvariable=self.voltage_var, font=("Courier New", 10)).grid(row=0, column=1, padx=5, pady=2, sticky="w")
        ttk.Label(proc_f, text="Fan Duty:").grid(row=1, column=0, padx=5, pady=2, sticky="w")
        ttk.Label(proc_f, textvariable=self.fan_duty_var, font=("Courier New", 10)).grid(row=1, column=1, padx=5, pady=2, sticky="w")
        ttk.Label(proc_f, text="Temperature:").grid(row=2, column=0, padx=5, pady=2, sticky="w")
        ttk.Label(proc_f, textvariable=self.temperature_var, font=("Courier New", 10)).grid(row=2, column=1, padx=5, pady=2, sticky="w")

        # --- Bottom part for raw input monitor ---
        in_f2 = ttk.LabelFrame(frame_io, text="Input Monitor")
        in_f2.pack(fill="both", expand=True, pady=5)
        
        monitor_btn_frame2 = ttk.Frame(in_f2)
        monitor_btn_frame2.pack(fill="x")
        ttk.Button(monitor_btn_frame2, text="Start Monitor", command=self.start_reading).pack(side="left", padx=5, pady=2)
        ttk.Button(monitor_btn_frame2, text="Stop Monitor", command=self.stop_reading).pack(side="left", padx=5, pady=2)
        ttk.Button(monitor_btn_frame2, text="Clear", command=self.clear_tab3_monitors).pack(side="left", padx=5, pady=2)
        
        self.monitor_text2 = tk.Text(in_f2, height=10, background="#f0f0f0")
        self.monitor_text2.pack(fill="both", expand=True, padx=5, pady=5)

    def clear_tab3_monitors(self):
        if self.monitor_text2:
            self.monitor_text2.delete('1.0', tk.END)
        self.voltage_var.set("N/A")
        self.fan_duty_var.set("N/A")
        self.temperature_var.set("N/A")

    def send_sequence2(self, commands):
        """Generic function to send a list of commands with 1s delay to tab 2."""
        def execute_step(index):
            if index < len(commands):
                self.out_entry2.delete(0, tk.END)
                self.out_entry2.insert(0, commands[index])
                self.send_output_report2()
                self.master.after(2000, lambda: execute_step(index + 1))
        execute_step(0)

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
            self.notebook.tab(self.tab_test2, state='normal')
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

    def send_output_report2(self):
        try:
            rid = int(self.rid_entry2.get(), 16)
            data_str = self.out_entry2.get().replace(" ", "")
            data = [int(data_str[i:i+2], 16) for i in range(0, len(data_str), 2)]
            buf = [rid] + data
            if self.ep_out:
                self.ep_out.write(buf)
            else:
                self.device.ctrl_transfer(0x21, 0x09, (0x02 << 8) | rid, self.active_interface, buf)
            self.monitor_text2.insert(tk.END, f"[SENT] ID:{hex(rid)} Data:{' '.join([f'{b:02X}' for b in data])}\n")
            self.monitor_text2.see(tk.END)
        except Exception as e: 
            messagebox.showerror("Write Error", str(e))

    def start_reading(self):
        if not self.ep_in:
            messagebox.showwarning("Warning", "No IN endpoint available.")
            return
        self.reading_status = True
        self._read_loop()

    def _process_incoming_data(self, data):
        # Display raw data in both monitors
        msg = f"[RECV] {' '.join([f'{b:02X}' for b in data])}\n"
        if self.monitor_text:
            self.monitor_text.insert(tk.END, msg)
            self.monitor_text.see(tk.END)
        if self.monitor_text2:
            self.monitor_text2.insert(tk.END, msg)
            self.monitor_text2.see(tk.END)

        # Check for specific report and process it for tab 3
        if len(data) >= 6 and data[0] == 0x20 and data[1] == 0xE1 and data[2] == 0x01 and data[3] == 0x10:
            voltage_byte = data[4]
            fan_duty_byte = data[5]
            
            # Calculate and display voltage
            voltage = (voltage_byte / 255.0) * 3.3
            self.voltage_var.set(f"{voltage:.2f} V")
            
            # Display fan duty
            self.fan_duty_var.set(f"{fan_duty_byte}")

            # Lookup and display temperature
            temp = self._get_temp_from_adc(voltage_byte)
            self.temperature_var.set(f"{temp} °C" if isinstance(temp, int) else temp)

    def _read_loop(self):
        if not self.reading_status or not self.device: return
        try:
            # Read data from the IN endpoint
            data = self.device.read(self.ep_in.bEndpointAddress, self.ep_in.wMaxPacketSize, timeout=20)
            if data:
                self._process_incoming_data(data)
        except usb.core.USBError:
            # This often happens on timeout, which is normal.
            pass 
        # Schedule the next read
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