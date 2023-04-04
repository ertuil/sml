from typing import Dict, Optional
import psutil
import time
import socket
import traceback
import pySMART
import platform
import os
from utils import _bps_value, _byte_value, _percent_value, get_current_time
from config import cpu_load_warn, cpu_load_critical, cpu_interval, mem_load_warn, mem_load_critical,\
                fs_usage_warn, fs_usage_critical, fs_filter,\
                net_send_warn, net_send_packet_warn, net_recv_warn, net_recv_packet_warn,\
                net_bps_critical, net_pps_critical, net_filter, net_interval,\
                temp_cpu_critical, temp_cpu_warn, temp_disk_critical, temp_disk_warn,\
                temp_critical_percent, temp_warn_percent, listen_map,\
                net_conn_warn, net_conn_critical, disk_io_time_warn, disk_write_critical,\
                disk_filter, disk_io_time_critical, disk_iops_critical, disk_iops_warn, disk_read_critical,\
                disk_read_warn, disk_write_warn, disk_interval


class Rule():
    def __init__(self, name: str, debug: bool = False):
        self.name = name
        self.debug = debug

    def stat(self):
        return {}

    def warn(self, stat: dict):
        return []

    def run(self, current_time_str: Optional[str] = None):
        if current_time_str is None:
            current_time_str = get_current_time()

        s = self.stat()
        w = self.warn(s)
        if len(w) > 0:
            w.extend(self.get_top_proc())
        return s, w

    def get_top_proc(self):
        return []


class CPURule(Rule):
    def __init__(self, name: str = "cpu", debug: bool = False):
        super().__init__(name, debug)
        self.cpu_load_warn = cpu_load_warn
        self.cpu_load_critical = cpu_load_critical
        self.cpu_interval = cpu_interval

        self.cpu_proc_top_k = 3

    def stat(self):
        cpu_percent = psutil.cpu_percent(interval=self.cpu_interval) / 100
        cpu_core = psutil.cpu_count()
        cpu_load = psutil.getloadavg()
        cpu_1min = cpu_load[0]/cpu_core
        cpu_5min = cpu_load[1]/cpu_core
        cpu_15min = cpu_load[1]/cpu_core
        return {"now": cpu_percent, "1min": cpu_1min, "5min": cpu_5min, "15min": cpu_15min}

    def warn(self, stat: Dict):
        if self.cpu_load_warn is None:
            return super().warn(stat)

        warn_msgs = []

        for item, value in stat.items():
            if self.cpu_load_critical is not None and value >= self.cpu_load_critical:
                warn_msgs.append(
                    f"[{self.name}-{item}] critical: {_percent_value(value)} \
(>= {_percent_value(self.cpu_load_critical)})")
                continue
            if value >= self.cpu_load_warn:
                warn_msgs.append(
                    f"[{self.name}-{item}] warning: {_percent_value(value)} (>= {_percent_value(self.cpu_load_warn)})")
        return warn_msgs

    def get_top_proc(self):
        proc_msgs = []

        cpu_usage_list = [p.as_dict(attrs=["pid", "name", "cpu_times"]) for p in psutil.process_iter()]
        cpu_usage_list.sort(key=lambda p: sum(p["cpu_times"][:2]), reverse=True)

        for p in cpu_usage_list[:min(self.cpu_proc_top_k, len(cpu_usage_list))]:
            proc_msgs.append(f"[{self.name}-proc] info: process {p['pid']} {p['name']} \
(CPU time: system {p['cpu_times'][0]} user {p['cpu_times'][1]})")
        return proc_msgs


class MemRule(Rule):
    def __init__(self, name: str = "mem", debug: bool = False):
        super().__init__(name, debug)
        self.mem_load_warn = mem_load_warn
        self.mem_load_critical = mem_load_critical

        self.mem_proc_top_k = 3

    def stat(self):
        virtual_mem = psutil.virtual_memory()
        mem_total = _byte_value(virtual_mem.total)
        mem_used = _byte_value(virtual_mem.used)
        mem_free = _byte_value(virtual_mem.available)

        mem_usage = virtual_mem.percent / 100
        mem_stat = {"total": mem_total, "used": mem_used, "free": mem_free, "usage": mem_usage}
        if platform.system() == "Linux":
            mem_stat["buffer"] = virtual_mem.buffers
            mem_stat["cache"] = virtual_mem.cached
        return mem_stat

    def warn(self, stat: dict):
        if self.mem_load_warn is None:
            return super().warn(stat)

        warn_msgs = []
        usage = stat["usage"]
        if self.mem_load_critical is not None and usage >= self.mem_load_critical:
            warn_msgs.append(f"[{self.name}-usage] critical: {_percent_value(usage)} \
(>= {_percent_value(self.mem_load_critical)})")
        elif usage >= self.mem_load_warn:
            warn_msgs.append(f"[{self.name}-usage] warning: {_percent_value(usage)} \
(>= {_percent_value(self.mem_load_warn)})")

        return warn_msgs

    def get_top_proc(self):
        proc_msgs = []

        mem_usage_list = [p.as_dict(attrs=["pid", "name", "memory_info"]) for p in psutil.process_iter()]
        mem_usage_list.sort(key=lambda p: p["memory_info"].rss, reverse=True)

        for p in mem_usage_list[:min(self.mem_proc_top_k, len(mem_usage_list))]:
            proc_msgs.append(f"[{self.name}-proc] info: process {p['pid']} {p['name']} \
(rss: {_byte_value(p['memory_info'].rss)}, vms: {_byte_value(p['memory_info'].vms)})")
        return proc_msgs


class FSRule(Rule):
    def __init__(self, name: str = "fs", debug: bool = False):
        super().__init__(name, debug)
        self.fs_usage_warn = fs_usage_warn
        self.fs_filter = fs_filter
        self.fs_usage_critical = fs_usage_critical
        if self.fs_usage_critical is None:
            self.fs_usage_critical = 0.999

    def stat(self):
        fs_stat = {}

        counted_device = []
        for disk in psutil.disk_partitions():
            if disk.device in counted_device:
                continue
            if self.fs_filter is None or disk.device in self.fs_filter:
                disk_usage = psutil.disk_usage(disk.mountpoint)
                disk_total = _byte_value(disk_usage.total)
                disk_used = _byte_value(disk_usage.used)
                disk_free = _byte_value(disk_usage.free)
                disk_percent = disk_usage.percent / 100

                fs_stat[f"{disk.device}-total"] = disk_total
                fs_stat[f"{disk.device}-used"] = disk_used
                fs_stat[f"{disk.device}-free"] = disk_free
                fs_stat[f"{disk.device}-usage"] = disk_percent
                counted_device.append(disk.device)
        return fs_stat

    def warn(self, stat: dict):
        if self.fs_usage_warn is None:
            return super().warn(stat)

        warn_msgs = []

        counted_device = []
        for disk in psutil.disk_partitions():
            if disk.device in counted_device:
                continue
            counted_device.append(disk.device)

            device_name = disk.device
            key = f"{device_name}-usage"
            usage = stat.get(key, 0)
            used = stat.get(f"{device_name}-used", "NaN")
            total = stat.get(f"{device_name}-total", "NaN")
            if self.fs_usage_critical is not None and usage >= self.fs_usage_critical:
                warn_msgs.append(f"[{self.name}-{device_name}] critical: {_percent_value(usage)} \
(>= {_percent_value(self.fs_usage_critical)}, {used}/{total})")
            elif usage >= self.fs_usage_warn:
                warn_msgs.append(f"[{self.name}-{device_name}] warning: {_percent_value(usage)} \
(>= {_percent_value(self.fs_usage_warn)}, {used}/{total})")
        return warn_msgs


class DiskRule(Rule):
    def __init__(self, name: str = "disk", debug: bool = False):
        super().__init__(name, debug)
        self.disk_multipler = 1024 * 1024

        self.disk_iops_critical = disk_iops_critical
        self.disk_iops_warn = disk_iops_warn
        self.disk_io_time_warn = disk_io_time_warn
        self.disk_io_time_critical = disk_io_time_critical
        self.disk_write_warn = disk_write_warn * self.disk_multipler
        self.disk_write_critical = disk_write_critical * self.disk_multipler
        self.disk_read_warn = disk_read_warn * self.disk_multipler
        self.disk_read_critical = disk_read_critical * self.disk_multipler
        self.disk_filter = disk_filter
        self.disk_interval = disk_interval
        self.existed_disks = []
        self.disk_proc_top_k = 3

        if platform.system() == "Windows":
            os.system("diskperf -y")

    def stat(self):
        disk_stat = {}
        self.existed_disks.clear()

        disk_old = psutil.disk_io_counters(perdisk=True, nowrap=True)
        if disk_old is None or len(disk_old) == 0:
            return disk_stat
        time.sleep(self.disk_interval)
        disk_new = psutil.disk_io_counters(perdisk=True, nowrap=True)
        if disk_new is None:
            return disk_stat

        for disk_name in disk_new.keys():
            if self.disk_filter is not None and disk_name not in self.disk_filter:
                continue
            if disk_name in self.existed_disks:
                continue
            self.existed_disks.append(disk_name)
            try:
                disk_stat[f"{disk_name}-read"] = (disk_new[disk_name].read_bytes - disk_old[disk_name].read_bytes) \
                    / self.disk_interval
                disk_stat[f"{disk_name}-write"] = (disk_new[disk_name].write_bytes - disk_old[disk_name].write_bytes) \
                    / self.disk_interval
                disk_stat[f"{disk_name}-iops"] = (disk_new[disk_name].read_count + disk_new[disk_name].write_count
                                                  - disk_old[disk_name].read_count - disk_old[disk_name].write_count) \
                    / self.disk_interval
            except Exception:
                disk_stat[f"{disk_name}-read"] = 0
                disk_stat[f"{disk_name}-write"] = 0
                disk_stat[f"{disk_name}-iops"] = 0

            if platform.system() == "Linux":
                disk_stat[f"{disk_name}-time"] = disk_new[disk_name].busy_time
            else:
                disk_stat[f"{disk_name}-time"] = 0

            try:
                d = pySMART.Device(disk_name)
                disk_stat[f"{disk_name}-SMART"] = d.assessment
                if len(d.tests) > 0:
                    disk_stat[f"{disk_name}-SMART-test"] = d.tests[0].status
            except Exception as e:
                print("[warning] S.M.A.R.T exam not executed", e)
        return disk_stat

    def warn(self, stat: dict):
        warn_msgs = []

        for disk_name in self.existed_disks:
            # check smart
            smart_result = stat.get(f"{disk_name}-SMART", None)
            if smart_result and "EMPTY" not in smart_result and "PASS" not in smart_result:
                warn_msgs.append(f"[{self.name}-{disk_name}] critical: SMART {smart_result}")

            smart_log_result = stat.get(f"{disk_name}-SMART-test", None)
            if smart_log_result and "without error" not in smart_log_result:
                warn_msgs.append(f"[{self.name}-{disk_name}] critical: SMART test{smart_log_result}")

            disk_read = stat[f"{disk_name}-read"]
            disk_write = stat[f"{disk_name}-read"]
            disk_iops = stat[f"{disk_name}-iops"]
            disk_time = stat[f"{disk_name}-time"]

            # read bytes
            if self.disk_read_critical is not None and disk_read > self.disk_read_critical:
                warn_msgs.append(f"[{self.name}-{disk_name}] critical: read {_bps_value(disk_read)} \
(>= {_bps_value(self.disk_read_critical)})")
            elif self.disk_read_warn is not None and disk_read > self.disk_read_warn:
                warn_msgs.append(f"[{self.name}-{disk_name}] warn: read {_bps_value(disk_read)} \
(>= {_bps_value(self.disk_read_warn)})")

            # write bytes
            if self.disk_write_critical is not None and disk_write > self.disk_write_critical:
                warn_msgs.append(f"[{self.name}-{disk_name}] critical: write {_bps_value(disk_write)} \
(>= {_bps_value(self.disk_write_critical)})")
            elif self.disk_write_warn is not None and disk_write > self.disk_write_warn:
                warn_msgs.append(f"[{self.name}-{disk_name}] warn: write {_byte_value(disk_write)} \
(>= {_byte_value(self.disk_write_warn)})")

            # read delay
            if self.disk_io_time_critical is not None and disk_time > self.disk_io_time_critical:
                warn_msgs.append(f"[{self.name}-{disk_name}] critical: io {disk_time} ms \
(>= {self.disk_io_time_critical} ms)")
            elif self.disk_io_time_warn is not None and disk_time > self.disk_io_time_warn:
                warn_msgs.append(f"[{self.name}-{disk_name}] warn: io {disk_time} ms \
(>= {disk_io_time_warn} ms)")

            # iops 
            if self.disk_iops_critical is not None and disk_iops > self.disk_iops_critical:
                warn_msgs.append(f"[{self.name}-{disk_name}] critical: {disk_iops} iops \
(>= {self.disk_iops_critical} iops)")
            elif self.disk_iops_warn is not None and disk_iops > self.disk_iops_warn:
                warn_msgs.append(f"[{self.name}-{disk_name}] warn: {disk_iops} iops \
(>= {disk_iops_warn} iops)")
        return warn_msgs

    def get_top_proc(self):
        proc_msgs = []

        disk_usage_list_old = {p.pid: p.info for p in psutil.process_iter(['name', 'pid', 'io_counters'])}
        time.sleep(self.disk_interval)
        disk_usage_list_new = {p.pid: p.info for p in psutil.process_iter(['name', 'pid', 'io_counters'])}

        disk_io_diff = []
        for pid, new_info in disk_usage_list_new.items():
            if pid not in disk_usage_list_old:
                continue
            old_info = disk_usage_list_old[pid]
            if new_info['io_counters'] is None or old_info['io_counters'] is None:
                continue
            name = new_info['name']
            new_disk_info = new_info['io_counters']
            old_disk_info = old_info['io_counters']
            disk_io_diff.append({"pid": pid,
                                 "name": name,
                                 "read": new_disk_info.read_bytes - old_disk_info.read_bytes,
                                 "write": new_disk_info.write_bytes - old_disk_info.write_bytes,
                                 "iops": new_disk_info.read_count+new_disk_info.write_count
                                - old_disk_info.read_count+old_disk_info.write_count,
                                 "total": new_disk_info.read_bytes - old_disk_info.read_bytes
                                + new_disk_info.write_bytes - old_disk_info.write_bytes
                                 })

        disk_io_diff.sort(key=lambda p: p["total"], reverse=True)

        for p in disk_io_diff[:min(self.disk_proc_top_k, len(disk_io_diff))]:
            proc_msgs.append(f"[{self.name}-proc] info: process {p['pid']} {p['name']} \
(read {_bps_value(p['read'])}, write {_bps_value(p['write'])}, {p['iops']} iops)")
        return proc_msgs


class NetRule(Rule):
    def __init__(self, name: str = "net", debug: bool = False):
        super().__init__(name, debug)
        self.mbps_multipler = 1024 * 1024
        self.net_send_warn = net_send_warn * self.mbps_multipler
        self.net_recv_warn = net_recv_warn * self.mbps_multipler
        self.net_send_packet_warn = net_send_packet_warn
        self.net_recv_packet_warn = net_recv_packet_warn
        self.net_bps_critical = net_bps_critical * self.mbps_multipler
        self.net_pps_critical = net_pps_critical
        self.net_filter = net_filter
        self.interval = net_interval

        self.count_ifaces = []

    def stat(self):
        net_stat = {}

        self.count_ifaces.clear()
        psutil.net_io_counters.cache_clear()

        net_addr = psutil.net_if_addrs()
        for iface, addr_list in net_addr.items():
            if self.net_filter is None or iface in self.net_filter:
                if iface not in self.count_ifaces:
                    self.count_ifaces.append(iface)
                for addr in addr_list:
                    if addr.family == psutil.AF_LINK:
                        net_stat[f"{iface}-mac"] = addr.address
                    if addr.family == socket.AF_INET:
                        net_stat[f"{iface}-ipv4"] = addr.address
                    if addr.family == socket.AF_INET6:
                        net_stat[f"{iface}-ipv6"] = addr.address

        # first count
        old_stat = {}
        net_io = psutil.net_io_counters(pernic=True, nowrap=True)
        if net_io is None:
            return net_stat
        for iface, result in net_io.items():
            old_stat[f"{iface}-send-byte"] = result.bytes_sent
            old_stat[f"{iface}-send-packet"] = result.packets_sent
            old_stat[f"{iface}-recv-byte"] = result.bytes_recv
            old_stat[f"{iface}-recv-packet"] = result.packets_recv

        time.sleep(self.interval)

        net_io = psutil.net_io_counters(pernic=True, nowrap=True)
        if net_io is None:
            return net_stat
        for iface, result in net_io.items():
            try:
                net_stat[f"{iface}-send-bps"] = (result.bytes_sent - old_stat[f"{iface}-send-byte"])/self.interval
                net_stat[f"{iface}-recv-bps"] = (result.bytes_recv - old_stat[f"{iface}-recv-byte"])/self.interval
                net_stat[f"{iface}-send-pps"] = (result.packets_sent - old_stat[f"{iface}-send-packet"])/self.interval
                net_stat[f"{iface}-recv-pps"] = (result.packets_recv - old_stat[f"{iface}-recv-packet"])/self.interval
            except KeyError:
                continue

        return net_stat

    def warn(self, net_stat: dict):
        warn_msgs = []

        for iface in self.count_ifaces:
            try:
                send_bps = net_stat[f"{iface}-send-bps"]
                recv_bps = net_stat[f"{iface}-recv-bps"]
                send_pps = net_stat[f"{iface}-send-pps"]
                recv_pps = net_stat[f"{iface}-recv-pps"]
            except KeyError:
                continue

            if self.net_bps_critical is not None and send_bps >= self.net_bps_critical:
                warn_msgs.append(f"[{self.name}-{iface}] send critical: {_bps_value(send_bps)} \
(>= {_bps_value(self.net_bps_critical)})")
            elif self.net_send_warn is not None and send_bps >= self.net_send_warn:
                warn_msgs.append(f"[{self.name}-{iface}] send warning: {_bps_value(send_bps)} \
(>= {_bps_value(self.net_send_warn)})")

            if self.net_bps_critical is not None and recv_bps >= self.net_bps_critical:
                warn_msgs.append(f"[{self.name}-{iface}] recv critical: {_bps_value(recv_bps)} \
(>= {_bps_value(self.net_bps_critical)})")
            elif self.net_recv_warn is not None and recv_bps >= self.net_recv_warn:
                warn_msgs.append(f"[{self.name}-{iface}] recv warning: {_bps_value(recv_bps)} \
(>= {_bps_value(self.net_recv_warn)})")

            if self.net_pps_critical is not None and send_pps >= self.net_pps_critical:
                warn_msgs.append(f"[{self.name}-{iface}] send critical: {send_pps} pps \
(>= {self.net_pps_critical} pps)")
            elif self.net_send_packet_warn is not None and send_pps >= self.net_send_packet_warn:
                warn_msgs.append(f"[{self.name}-{iface}] send warning: {send_pps} pps \
(>= {self.net_send_packet_warn} pps)")

            if self.net_pps_critical is not None and recv_pps >= self.net_pps_critical:
                warn_msgs.append(f"[{self.name}-{iface}] recv critical: {recv_pps} pps \
(>= {self.net_pps_critical} pps)")
            elif self.net_recv_packet_warn is not None and recv_pps >= self.net_recv_packet_warn:
                warn_msgs.append(f"[{self.name}-{iface}] recv warning: {recv_pps} pps \
(>= {self.net_recv_packet_warn} pps)")
        return warn_msgs


class ConnRule(Rule):
    def __init__(self, name: str, debug: bool = False):
        super().__init__(name, debug)
        self.mbps_multipler = 1024 * 1024
        self.net_conn_warn = net_conn_warn
        self.net_conn_critical = net_conn_critical
        self.net_proc_top_k = 3

    def stat(self):
        net_stat = {}
        net_conn = psutil.net_connections("inet")
        tcp_conn = psutil.net_connections("tcp")
        udp_conn = psutil.net_connections("udp")

        net_stat["net-conn"] = len(net_conn)
        net_stat["tcp-conn"] = len(tcp_conn)
        net_stat["udp-conn"] = len(udp_conn)
        return net_stat

    def warn(self, net_stat: dict):
        warn_msgs = []
        net_conn = net_stat["net-conn"]
        tcp_conn = net_stat["tcp-conn"]
        udp_conn = net_stat["udp-conn"]

        if self.net_conn_critical is not None and net_conn >= self.net_conn_critical:
            warn_msgs.append(f"[{self.name}] net connection critical {net_conn} (>= {self.net_conn_critical})")
        elif net_conn >= self.net_conn_warn:
            warn_msgs.append(f"[{self.name}] net connection warn {net_conn} (>= {self.net_conn_warn})")

        if self.net_conn_critical is not None and tcp_conn >= self.net_conn_critical:
            warn_msgs.append(f"[{self.name}] tcp connection critical {tcp_conn} (>= {self.net_conn_critical})")
        elif tcp_conn >= self.net_conn_warn:
            warn_msgs.append(f"[{self.name}] tcp connection warn {tcp_conn} (>= {self.net_conn_warn})")

        if self.net_conn_critical is not None and udp_conn >= self.net_conn_critical:
            warn_msgs.append(f"[{self.name}] udp connection critical {udp_conn} (>= {self.net_conn_critical})")
        elif udp_conn >= self.net_conn_warn:
            warn_msgs.append(f"[{self.name}] udp connection warn {udp_conn} (>= {self.net_conn_warn})")
        return warn_msgs

    def get_top_proc(self):
        proc_msgs = []

        net_usage_list = [p.as_dict(attrs=["pid", "name", "connections"]) for p in psutil.process_iter()]
        print(net_usage_list)
        net_usage_list.sort(key=lambda p: len(p["connections"]) if p["connections"] is not None else 0, reverse=True)

        for p in net_usage_list[:min(self.net_proc_top_k, len(net_usage_list))]:
            proc_msgs.append(f"[{self.name}-proc] info: process {p['pid']} {p['name']} \
(connection: {len(p['connections'])})")
        return proc_msgs


class TempRule(Rule):
    def __init__(self, name: str = "temperature", debug: bool = False):
        super().__init__(name, debug)
        self.temp_cpu_warn = temp_cpu_warn
        self.temp_disk_warn = temp_disk_warn
        self.temp_warn_percent = temp_warn_percent if temp_warn_percent is not None else 1
        self.temp_cpu_critical = temp_cpu_critical if temp_cpu_critical is not None else 105
        self.temp_disk_critical = temp_disk_critical if temp_disk_critical is not None else 100
        self.temp_critical_percent = temp_critical_percent if temp_critical_percent is not None else 1

    def stat(self):
        temp_stat = {}
        temp_results = psutil.sensors_temperatures()

        for key, temps in temp_results.items():
            for t in temps:
                temp_stat[f"{key}-{t.label}"] = t
                t.critical

        return temp_stat

    def warn(self, stat):

        warn_msgs = []
        for label, temp in stat.items():
            if temp.critical is not None:
                if self.temp_critical_percent is not None and\
                   temp.current >= temp.critical * self.temp_critical_percent:
                    warn_msgs.append(f"[{self.name}-{label}] critical: {temp.current} \
(>= {temp.critical * self.temp_critical_percent}, crit. temp.: {temp.critical})")
                elif temp.current >= temp.critical * self.temp_warn_percent:
                    warn_msgs.append(f"[{self.name}-{label}] warning: {temp.current} \
(>= {temp.critical * self.temp_warn_percent}, crit. temp.: {temp.critical})")

            if "coretemp" in label or "cpu" in label or "Package id" in label or "Core" in label:
                if self.temp_cpu_critical is not None and temp.current >= self.temp_cpu_critical:
                    warn_msgs.append(f"[{self.name}-{label}] critical: {temp.current} \
(>= {self.temp_cpu_critical})")
                elif temp.current >= self.temp_cpu_warn:
                    warn_msgs.append(f"[{self.name}-{label}] warning: {temp.current} \
(>= {self.temp_cpu_warn})")

            if "nvmi" in label or "hdd" in label or "disk" in label:
                if self.temp_disk_critical is not None and temp.current >= self.temp_disk_critical:
                    warn_msgs.append(f"[{self.name}-{label}] critical: {temp.current} \
(>= {self.temp_disk_critical})")
                elif temp.current >= self.temp_disk_warn:
                    warn_msgs.append(f"[{self.name}-{label}] warning: {temp.current} \
(>= {self.temp_disk_warn})")
        return warn_msgs


class ListenRule(Rule):
    def __init__(self, name: str = "listen", debug: bool = False):
        super().__init__(name, debug)
        self.listen_map = {}
        for r in listen_map:
            try:
                name = r[0]
                protocol = r[1]
                port = r[2]
                key = f"{protocol}{port}"
                self.listen_map[key] = {"name": name, "port": port, "protocol": protocol, "checked": False}
            except Exception as e:
                traceback.print_exc(e)
                continue

    def stat(self):
        listen_stat = {}
        conns = psutil.net_connections(kind='tcp')
        for c in conns:
            if c.status == psutil.CONN_LISTEN:
                protocol = "tcp"
                port = c.laddr.port
                key = f"{protocol}{port}"
                listen_stat[key] = {"protocol": protocol, "port": port}

        conns = psutil.net_connections(kind='udp')
        for c in conns:
            if len(c.raddr) == 0:
                protocol = "udp"
                port = c.laddr.port
                key = f"{protocol}{port}"
                listen_stat[key] = {"protocol": protocol, "port": port}

        return listen_stat

    def warn(self, stat: dict):
        warn_msgs = []
        for key in stat.keys():
            if key in self.listen_map:
                self.listen_map[key]["checked"] = True

        for key, value in self.listen_map.items():
            if not value["checked"]:
                name = value["name"]
                protocol = value["protocol"]
                port = value["port"]
                warn_msgs.append(f"[{self.name}-{name}] critical: service {name} on {protocol}:{port} not listened")
        return warn_msgs
