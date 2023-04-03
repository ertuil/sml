from typing import Optional
import psutil
import time
import socket
import traceback
from utils import _bps_value, _byte_value, _percent_value, get_current_time

from config import cpu_load_warn, cpu_load_critical, cpu_interval, mem_load_warn, mem_load_critical,\
                disk_load_warn, disk_load_critical, disk_filter,\
                net_send_warn, net_send_packet_warn, net_recv_warn, net_recv_packet_warn,\
                net_bps_critical, net_pps_critical, net_filter, net_interval,\
                temp_cpu_critical, temp_cpu_warn, temp_disk_critical, temp_disk_warn,\
                temp_critical_percent, temp_warn_percent, listen_map


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
        return s, w


class CPURule(Rule):
    def __init__(self, name: str = "cpu", debug: bool = False):
        super().__init__(name, debug)
        self.cpu_load_warn = cpu_load_warn
        self.cpu_load_critical = cpu_load_critical
        self.cpu_interval = cpu_interval

    def stat(self):
        cpu_percent = psutil.cpu_percent(interval=self.cpu_interval) / 100
        cpu_core = psutil.cpu_count()
        cpu_load = psutil.getloadavg()
        cpu_1min = cpu_load[0]/cpu_core
        cpu_5min = cpu_load[1]/cpu_core
        cpu_15min = cpu_load[1]/cpu_core
        return {"now": cpu_percent, "1min": cpu_1min, "5min": cpu_5min, "15min": cpu_15min}

    def warn(self, stat: dict):
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


class MemRule(Rule):
    def __init__(self, name: str = "mem", debug: bool = False):
        super().__init__(name, debug)
        self.mem_load_warn = mem_load_warn
        self.mem_load_critical = mem_load_critical

    def stat(self):
        virtual_mem = psutil.virtual_memory()
        mem_total = _byte_value(virtual_mem.total)
        mem_used = _byte_value(virtual_mem.used)
        mem_free = _byte_value(
            virtual_mem.free + virtual_mem.buffers + virtual_mem.cached)
        mem_usage = virtual_mem.percent / 100
        return {"total": mem_total, "used": mem_used, "free": mem_free, "usage": mem_usage}

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


class DiskRule(Rule):
    def __init__(self, name: str = "disk", debug: bool = False):
        super().__init__(name, debug)
        self.disk_load_warn = disk_load_warn
        self.disk_filter = disk_filter
        self.disk_load_critical = disk_load_critical
        if self.disk_load_critical is None:
            self.disk_load_critical = 0.999

    def stat(self):
        disk_stat = {}

        counted_device = []
        for disk in psutil.disk_partitions():
            if disk.device in counted_device:
                continue
            if self.disk_filter is None or disk.device in self.disk_filter:
                disk_usage = psutil.disk_usage(disk.mountpoint)
                disk_total = _byte_value(disk_usage.total)
                disk_used = _byte_value(disk_usage.used)
                disk_free = _byte_value(disk_usage.free)
                disk_percent = disk_usage.percent / 100

                disk_stat[f"{disk.device}-total"] = disk_total
                disk_stat[f"{disk.device}-used"] = disk_used
                disk_stat[f"{disk.device}-free"] = disk_free
                disk_stat[f"{disk.device}-usage"] = disk_percent
                counted_device.append(disk.device)
        return disk_stat

    def warn(self, stat: dict):
        if self.disk_load_warn is None:
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
            if self.disk_load_critical is not None and usage >= self.disk_load_critical:
                warn_msgs.append(f"[{self.name}-{device_name}] critical: {_percent_value(usage)} \
(>= {_percent_value(self.disk_load_critical)}, {used}/{total})")
            elif usage >= self.disk_load_warn:
                warn_msgs.append(f"[{self.name}-{device_name}] warning: {_percent_value(usage)} \
(>= {_percent_value(self.disk_load_warn)}, {used}/{total})")
        return warn_msgs


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
        for iface, result in net_io.items():
            old_stat[f"{iface}-send-byte"] = result.bytes_sent
            old_stat[f"{iface}-send-packet"] = result.packets_sent
            old_stat[f"{iface}-recv-byte"] = result.bytes_recv
            old_stat[f"{iface}-recv-packet"] = result.packets_recv

        time.sleep(self.interval)

        net_io = psutil.net_io_counters(pernic=True, nowrap=True)
        for iface, result in net_io.items():
            net_stat[f"{iface}-send-bps"] = (result.bytes_sent - old_stat[f"{iface}-send-byte"])/self.interval
            net_stat[f"{iface}-recv-bps"] = (result.bytes_recv - old_stat[f"{iface}-recv-byte"])/self.interval
            net_stat[f"{iface}-send-pps"] = (result.packets_sent - old_stat[f"{iface}-send-packet"])/self.interval
            net_stat[f"{iface}-recv-pps"] = (result.packets_recv - old_stat[f"{iface}-recv-packet"])/self.interval

        return net_stat

    def warn(self, net_stat: dict):
        warn_msgs = []

        for iface in self.count_ifaces:
            send_bps = net_stat[f"{iface}-send-bps"]
            recv_bps = net_stat[f"{iface}-recv-bps"]
            send_pps = net_stat[f"{iface}-send-pps"]
            recv_pps = net_stat[f"{iface}-recv-pps"]

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
