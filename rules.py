from typing import Dict, Optional
import psutil
import time
import socket
import traceback
import pySMART
import docker
import platform
import os
from utils import _bps_value, _byte_value, _percent_value, get_current_time
from config import cpu_load_warn, cpu_load_critical, cpu_interval, mem_load_warn, mem_load_critical,\
                fs_usage_warn, fs_usage_critical, fs_filter,\
                net_io_warn, net_io_critical, net_pps_warn, net_pps_critical,\
                net_filter, net_interval,\
                temp_cpu_critical, temp_cpu_warn, temp_disk_critical, temp_disk_warn,\
                temp_critical_percent, temp_warn_percent, listen_map,\
                net_conn_warn, net_conn_critical, disk_usage_warn, disk_write_critical,\
                disk_filter, disk_usage_critical, disk_iops_critical, disk_iops_warn, disk_read_critical,\
                disk_read_warn, disk_write_warn, disk_interval, docker_url, docker_watch_containers

try:
    from config import net_max_bandwidth
except ImportError:
    net_max_bandwidth = 1000


class Rule():
    def __init__(self, name: str, debug: bool = False):
        self.name = name
        self.debug = debug

        self.msgs = []
        self.system = platform.system()
        self.is_root = self.check_admin()
        self.pid = os.getpid()

    def stat(self):
        return {}

    def check(self, stat: dict):
        pass

    def run(self, current_time_str: Optional[str] = None):
        if current_time_str is None:
            current_time_str = get_current_time()

        self._clear_msgs()
        try:
            s = self.stat()
            self.check(s)
        except Exception as e:
            if self.debug:
                traceback.print_exc()
            self.critical("core", f"run monitor error: {e}")
            return {}, self.msgs
        try:
            if len(self.msgs) > 0:
                self.get_top_proc()
        except Exception as e:
            if self.debug:
                traceback.print_exc()
            self.critical("core", f"enumerate processes error: {e}")
            return s, self.msgs
        if self.debug:
            self.debug_stat(s)
        return s, self.msgs

    def get_top_proc(self):
        pass

    def get_proc_name(self, process: psutil.Process):
        process_name = "None"
        if self.system != "Windows" and process.cmdline() is not None and len(process.cmdline()) > 0:
            process_name = " ".join(process.cmdline())
        elif process.name() != "":
            process_name = process.name()
        else:
            process_name = process.exe()
        if len(process_name) > 128:
            process_name = process_name[:125] + "..."
        return process_name

    def check_admin(self):
        is_root = False
        if platform.system() in ["Linux", "Darwin"]:
            if os.getuid() == 0:
                is_root = True
        if platform.system() == "Windows":
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                is_root = True
        return is_root

    def _clear_msgs(self):
        self.msgs.clear()

    def warning(self, obj: str, msg: str):
        self.msgs.append({"level": "warning", "msg": f"[{self.name}-{obj}] {msg}"})

    def info(self, obj: str, msg: str):
        self.msgs.append({"level": "info", "msg": f"[{self.name}-{obj}] {msg}"})

    def critical(self, obj: str, msg: str):
        self.msgs.append({"level": "critical", "msg": f"[{self.name}-{obj}] {msg}"})

    def debug_stat(self, msg: str):
        self.msgs.append({"level": "debug", "msg": f"[{self.name}] {msg}"})


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

    def check(self, stat: Dict):
        if self.cpu_load_warn is None:
            return super().warn(stat)

        for item, value in stat.items():
            if self.cpu_load_critical is not None and value >= self.cpu_load_critical:
                self.critical(item, f"{_percent_value(value)} (>= {_percent_value(self.cpu_load_critical)})")
                continue
            if value >= self.cpu_load_warn:
                self.warning(item, f"{_percent_value(value)} (>= {_percent_value(self.cpu_load_warn)})")

    def get_top_proc(self):
        cpu_core = psutil.cpu_count()
        for p in psutil.process_iter():
            p.cpu_percent(interval=None)

        time.sleep(self.cpu_interval)
        cpu_usage_list = []
        for p in psutil.process_iter():
            pid = p.pid
            if pid == self.pid:
                continue
            name = self.get_proc_name(p)
            cpu_percentage = p.cpu_percent(interval=None)
            cpu_usage_list.append({"pid": pid, "name": name, "cpu": cpu_percentage})
        cpu_usage_list.sort(key=lambda p: p["cpu"], reverse=True)

        for p in cpu_usage_list[:min(self.cpu_proc_top_k, len(cpu_usage_list))]:
            self.info("proc", f"id: {p['pid']} {p['name']} (*CPU {_percent_value(p['cpu']/cpu_core)})")


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
            mem_stat["buffer"] = _byte_value(virtual_mem.buffers)
            mem_stat["cache"] = _byte_value(virtual_mem.cached)
        return mem_stat

    def check(self, stat: dict):
        if self.mem_load_warn is None:
            return super().warn(stat)

        usage = stat["usage"]
        if self.mem_load_critical is not None and usage >= self.mem_load_critical:
            self.critical("usage", f"{_percent_value(usage)} \
(>= {_percent_value(self.mem_load_critical)})")
        elif usage >= self.mem_load_warn:
            self.warning("usage", f"{_percent_value(usage)} \
(>= {_percent_value(self.mem_load_warn)})")

    def get_top_proc(self):
        mem_usage_list = [p for p in psutil.process_iter() if p.pid != self.pid]
        mem_usage_list.sort(key=lambda p: p.memory_info().rss, reverse=True)

        for p in mem_usage_list[:min(self.mem_proc_top_k, len(mem_usage_list))]:
            self.info("proc", f"id: {p.pid} {self.get_proc_name(p)} \
(*rss: {_byte_value(p.memory_info().rss)}, vms: {_byte_value(p.memory_info().vms)})")


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

    def check(self, stat: dict):
        if self.fs_usage_warn is None:
            return super().warn(stat)
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
                self.critical(device_name, f"{_percent_value(usage)} \
(>= {_percent_value(self.fs_usage_critical)}, {used}/{total})")
            elif usage >= self.fs_usage_warn:
                self.warning(device_name, f"{_percent_value(usage)} \
(>= {_percent_value(self.fs_usage_warn)}, {used}/{total})")

        if self.fs_filter is not None:
            for test_fs in self.fs_filter:
                if test_fs not in counted_device:
                    self.warning(test_fs, "filesystem not found")


class DiskRule(Rule):
    def __init__(self, name: str = "disk", debug: bool = False):
        super().__init__(name, debug)
        self.disk_multipler = 1024 * 1024

        self.disk_iops_critical = disk_iops_critical
        self.disk_iops_warn = disk_iops_warn
        self.disk_usage_warn = disk_usage_warn
        self.disk_usage_critical = disk_usage_critical
        self.disk_write_warn = disk_write_warn * self.disk_multipler
        self.disk_write_critical = disk_write_critical * self.disk_multipler
        self.disk_read_warn = disk_read_warn * self.disk_multipler
        self.disk_read_critical = disk_read_critical * self.disk_multipler
        self.disk_filter = disk_filter
        self.disk_interval = disk_interval
        self.existed_disks = []
        self.disk_proc_top_k = 3

        self.warn_iops = False
        self.warn_bytes = False

        if platform.system() == "Windows":
            os.system("diskperf -y")

    def stat(self):
        disk_stat = {}
        self.existed_disks.clear()
        self.warn_iops = False
        self.warn_bytes = False

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
                disk_stat[f"{disk_name}-time"] = (disk_new[disk_name].busy_time - disk_old[disk_name].busy_time)\
                    / (self.disk_interval * 1000)
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

    def check(self, stat: dict):
        self.warn_bytes = False
        self.warn_iops = False

        if self.disk_filter is not None:
            for disk in self.disk_filter:
                if disk not in self.existed_disks:
                    self.warning(disk, "disk not found")

        for disk_name in self.existed_disks:
            # check smart
            smart_result = stat.get(f"{disk_name}-SMART", None)
            if smart_result and "EMPTY" not in smart_result and "PASS" not in smart_result:
                self.critical(disk_name, f"SMART {smart_result}")

            smart_log_result = stat.get(f"{disk_name}-SMART-test", None)
            if smart_log_result and "without error" not in smart_log_result:
                self.critical(disk_name, f"SMART test log {smart_log_result}")

            disk_read = stat[f"{disk_name}-read"]
            disk_write = stat[f"{disk_name}-read"]
            disk_iops = stat[f"{disk_name}-iops"]
            disk_time = stat[f"{disk_name}-time"]

            # read bytes
            if self.disk_read_critical is not None and disk_read >= self.disk_read_critical:
                self.critical(disk_name, f"read {_bps_value(disk_read)} \
(>= {_bps_value(self.disk_read_critical)})")
                self.warn_bytes = True
            elif self.disk_read_warn is not None and disk_read >= self.disk_read_warn:
                self.warning(disk_name, f"read {_bps_value(disk_read)} \
(>= {_bps_value(self.disk_read_warn)})")
                self.warn_bytes = True

            # write bytes
            if self.disk_write_critical is not None and disk_write >= self.disk_write_critical:
                self.critical(disk_name, f"write {_bps_value(disk_write)} \
(>= {_bps_value(self.disk_write_critical)})")
                self.warn_bytes = True
            elif self.disk_write_warn is not None and disk_write >= self.disk_write_warn:
                self.warning(disk_name, f"write {_byte_value(disk_write)} \
(>= {_byte_value(self.disk_write_warn)})")
                self.warn_bytes = True

            # busy time percent
            if self.disk_usage_critical is not None and disk_time >= self.disk_usage_critical:
                self.critical(disk_name, f"busy {_percent_value(disk_time)} \
(>= {_percent_value(self.disk_usage_critical)})")
                self.warn_iops = True
            elif self.disk_usage_warn is not None and disk_time >= self.disk_usage_warn:
                self.warning(disk_name, f"busy {_percent_value(disk_time)} \
(>= {_percent_value(self.disk_usage_warn)})")
                self.warn_iops = True

            # iops
            if self.disk_iops_critical is not None and disk_iops >= self.disk_iops_critical:
                self.critical(disk_name, f"{disk_iops} iops (>= {self.disk_iops_critical} iops)")
                self.warn_iops = True
            elif self.disk_iops_warn is not None and disk_iops >= self.disk_iops_warn:
                self.warning(disk_name, f"{disk_iops} iops (>= {disk_iops_warn} iops)")
                self.warn_iops = True

    def get_top_proc(self):
        if self.system in ["Linux", "Darwin"] and not self.is_root:
            return

        disk_usage_list_old = {}
        for p in psutil.process_iter():
            old_io = p.io_counters()
            if old_io is None:
                continue
            disk_usage_list_old[p.pid] = old_io

        time.sleep(self.disk_interval)
        # disk_usage_list_new = {p.pid: p for p in psutil.process_iter()}

        disk_io_diff = []
        for p in psutil.process_iter():
            if self.pid == p.pid:
                continue
            if p.pid not in disk_usage_list_old:
                continue
            old_io = disk_usage_list_old[p.pid]
            new_io = p.io_counters()
            if new_io is None:
                continue

            disk_io_diff.append({"pid": p.pid,
                                 "name": self.get_proc_name(p),
                                 "read": (new_io.read_bytes - old_io.read_bytes)/self.disk_interval,
                                 "write": (new_io.write_bytes - old_io.write_bytes)/disk_interval,
                                 "iops": (new_io.read_count+new_io.write_count
                                          - old_io.read_count-old_io.write_count)/self.disk_interval,
                                 "total": (new_io.read_bytes - old_io.read_bytes
                                           + new_io.write_bytes - old_io.write_bytes)/self.disk_interval
                                 })

        if self.warn_bytes:
            disk_io_diff.sort(key=lambda p: p["total"], reverse=True)

            for p in disk_io_diff[:min(self.disk_proc_top_k, len(disk_io_diff))]:
                self.info("proc", f"id: {p['pid']} {p['name']} \
    (*total: {_bps_value(p['total'])},read {_bps_value(p['read'])}, write {_bps_value(p['write'])}, {p['iops']} iops)")

        if self.warn_iops:
            disk_io_diff.sort(key=lambda p: p["iops"], reverse=True)

            for p in disk_io_diff[:min(self.disk_proc_top_k, len(disk_io_diff))]:
                self.info("proc", f"id: {p['pid']} {p['name']} \
    (*{p['iops']} iops, read {_bps_value(p['read'])}, write {_bps_value(p['write'])})")


class NetRule(Rule):
    def __init__(self, name: str = "net", debug: bool = False):
        super().__init__(name, debug)
        self.mbps_multipler = 1024 * 1024
        self.net_io_warn = net_io_warn
        self.net_io_critical = net_io_critical
        self.net_pps_warn = net_pps_warn
        self.net_pps_critical = net_pps_critical
        self.net_filter = net_filter
        self.interval = net_interval
        self.net_max_bandwidth = net_max_bandwidth if net_max_bandwidth is not None else 1000

        self.count_ifaces = []

    def stat(self):
        net_stat = {}

        self.count_ifaces.clear()
        psutil.net_io_counters.cache_clear()

        net_addr = psutil.net_if_addrs()
        net_info = psutil.net_if_stats()
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
                if iface in net_info:
                    if_stat = net_info[iface]
                    mul = 1
                    if if_stat.duplex == psutil.NIC_DUPLEX_HALF:
                        mul = 0.5
                    speed = if_stat.speed
                    if "lo" in iface or "Loopback" in iface:
                        # 100 GBps for lookback device
                        speed = 100000 * self.mbps_multipler
                    elif speed == 0 or speed > self.net_max_bandwidth:
                        # support default is 1 GBps
                        speed = self.net_max_bandwidth * self.mbps_multipler * mul
                    else:
                        speed = speed * self.mbps_multipler * mul
                    net_stat[f"{iface}-max"] = speed
                else:
                    # support default is 1 GBps
                    net_stat[f"{iface}-max"] = self.net_max_bandwidth * self.mbps_multipler

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
            if self.net_filter is not None and iface not in self.net_filter:
                continue
            try:
                net_stat[f"{iface}-send-bps"] = (result.bytes_sent - old_stat[f"{iface}-send-byte"])/self.interval
                net_stat[f"{iface}-recv-bps"] = (result.bytes_recv - old_stat[f"{iface}-recv-byte"])/self.interval
                net_stat[f"{iface}-send-pps"] = (result.packets_sent - old_stat[f"{iface}-send-packet"])/self.interval
                net_stat[f"{iface}-recv-pps"] = (result.packets_recv - old_stat[f"{iface}-recv-packet"])/self.interval
            except KeyError:
                continue

        return net_stat

    def check(self, net_stat: dict):
        if isinstance(self.net_filter, list):
            for iface in self.net_filter:
                if iface not in self.count_ifaces:
                    self.warning(iface, "network interface not found")

        for iface in self.count_ifaces:
            try:
                send_bps = net_stat[f"{iface}-send-bps"]
                recv_bps = net_stat[f"{iface}-recv-bps"]
                send_pps = net_stat[f"{iface}-send-pps"]
                recv_pps = net_stat[f"{iface}-recv-pps"]
                speed = net_stat[f"{iface}-max"]
            except KeyError:
                continue

            if self.net_io_critical is not None and send_bps >= self.net_io_critical * speed:
                self.critical(iface, f"send {_bps_value(send_bps)} (>= {self.net_io_critical}x {_bps_value(speed)} \
= {_bps_value(self.net_io_critical*speed)})")
            elif self.net_io_warn is not None and send_bps >= self.net_io_warn * speed:
                self.warning(iface, f"send {_bps_value(send_bps)} (>= {self.net_io_warn}x {_bps_value(speed)} \
= {_bps_value(self.net_io_warn*speed)})")

            if self.net_io_critical is not None and recv_bps >= self.net_io_critical * speed:
                self.critical(iface, f"recv {_bps_value(recv_bps)} (>= {self.net_io_critical}x {_bps_value(speed)} \
= {_bps_value(self.net_io_critical*speed)})")
            elif self.net_io_warn is not None and recv_bps >= self.net_io_warn * speed:
                self.warning(iface, f"recv {_bps_value(recv_bps)} (>= {self.net_io_warn}x {_bps_value(speed)} \
= {_bps_value(self.net_io_warn*speed)})")

            if self.net_pps_critical is not None and send_pps >= self.net_pps_critical:
                self.critical(iface, f"send {send_pps} pps (>= {self.net_pps_critical} pps)")
            elif self.net_pps_warn is not None and send_pps >= self.net_pps_warn:
                self.warning(iface, f"send {send_pps} pps (>= {self.net_pps_warn} pps)")

            if self.net_pps_critical is not None and recv_pps >= self.net_pps_critical:
                self.critical(iface, f"recv {recv_pps} pps (>= {self.net_pps_critical} pps)")
            elif self.net_pps_warn is not None and recv_pps >= self.net_pps_warn:
                self.warning(iface, f"recv {recv_pps} pps (>= {self.net_pps_warn} pps)")


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

    def check(self, net_stat: dict):
        net_conn = net_stat["net-conn"]
        tcp_conn = net_stat["tcp-conn"]
        udp_conn = net_stat["udp-conn"]

        if self.net_conn_critical is not None and net_conn >= self.net_conn_critical:
            self.critical("total conn", f"{net_conn} (>= {self.net_conn_critical})")
        elif net_conn >= self.net_conn_warn:
            self.warning("total conn", f"{net_conn} (>= {self.net_conn_warn})")

        if self.net_conn_critical is not None and tcp_conn >= self.net_conn_critical:
            self.critical("tcp conn", f"{tcp_conn} (>= {self.net_conn_critical})")
        elif tcp_conn >= self.net_conn_warn:
            self.warning("tcp conn", f"{tcp_conn} (>= {self.net_conn_warn})")

        if self.net_conn_critical is not None and udp_conn >= self.net_conn_critical:
            self.critical("udp conn", f"{udp_conn} (>= {self.net_conn_critical})")
        elif udp_conn >= self.net_conn_warn:
            self.warning("udp conn", f"{udp_conn} (>= {self.net_conn_warn})")

    def get_top_proc(self):
        if self.system in ["Linux", "Darwin"] and not self.is_root:
            return
        net_usage_list = [p for p in psutil.process_iter() if self.pid != p.pid]
        net_usage_list.sort(key=lambda p: len(p.connections()) if p.connections() is not None else 0, reverse=True)

        for p in net_usage_list[:min(self.net_proc_top_k, len(net_usage_list))]:
            self.info("proc", f"id {p.pid} {self.get_proc_name(p)} \
(*connection: {len(p.connections())})")


class TempRule(Rule):
    def __init__(self, name: str = "temp", debug: bool = False):
        super().__init__(name, debug)
        self.temp_cpu_warn = temp_cpu_warn
        self.temp_disk_warn = temp_disk_warn
        self.temp_warn_percent = temp_warn_percent if temp_warn_percent is not None else 1
        self.temp_cpu_critical = temp_cpu_critical if temp_cpu_critical is not None else 105
        self.temp_disk_critical = temp_disk_critical if temp_disk_critical is not None else 100
        self.temp_critical_percent = temp_critical_percent if temp_critical_percent is not None else 1
        self.warn_cpu = False
        self.warn_disk = False

    def stat(self):
        temp_stat = {}
        temp_results = psutil.sensors_temperatures()

        for key, temps in temp_results.items():
            for t in temps:
                temp_stat[f"{key}-{t.label}"] = t

        return temp_stat

    def check(self, stat):
        self.warn_cpu = False
        self.warn_disk = False
        for label, temp in stat.items():
            if temp.critical is not None:
                if self.temp_critical_percent is not None and\
                   temp.current >= temp.critical * self.temp_critical_percent:
                    self.critical(label, f"{temp.current} \
(>= {temp.critical * self.temp_critical_percent}, crit. temp.: {temp.critical})")
                elif temp.current >= temp.critical * self.temp_warn_percent:
                    self.warning(label, f"{temp.current} \
(>= {temp.critical * self.temp_warn_percent}, crit. temp.: {temp.critical})")

            if "coretemp" in label or "cpu" in label or "Package id" in label or "Core" in label:
                if self.temp_cpu_critical is not None and temp.current >= self.temp_cpu_critical:
                    self.warn_cpu = True
                    self.critical(label, f"{temp.current} (>= {self.temp_cpu_critical})")
                elif temp.current >= self.temp_cpu_warn:
                    self.warn_cpu = True
                    self.warning(label, f"{temp.current} (>= {self.temp_cpu_warn})")

            if "nvme" in label or "hdd" in label or "disk" in label:
                if self.temp_disk_critical is not None and temp.current >= self.temp_disk_critical:
                    self.warn_disk = True
                    self.critical(label, f"{temp.current} \
(>= {self.temp_disk_critical})")
                elif temp.current >= self.temp_disk_warn:
                    self.warn_disk = True
                    self.warning(label, f"{temp.current} \
(>= {self.temp_disk_warn})")

    def get_top_proc(self):
        if self.warn_cpu:
            cpu_rule = CPURule(name=self.name+"-cpu", debug=self.debug)
            cpu_rule.get_top_proc()
            for msg in cpu_rule.msgs:
                self.msgs.append(msg)
        if self.warn_disk:
            disk_rule = DiskRule(name=self.name+"-disk", debug=self.debug)
            disk_rule.warn_bytes = True
            disk_rule.get_top_proc()
            for msg in disk_rule.msgs:
                self.msgs.append(msg)


class ListenRule(Rule):
    def __init__(self, name: str = "listen", debug: bool = False):
        super().__init__(name, debug)
        self.listen_map = {}
        if listen_map is not None:
            for r in listen_map:
                try:
                    name = r[0]
                    protocol = r[1]
                    port = r[2]
                    key = f"{protocol}{port}"
                    self.listen_map[key] = {"name": name, "port": port, "protocol": protocol, "checked": False}
                except Exception as e:
                    if self.debug:
                        traceback.print_exc()
                    print(f"load listen rules failed, {e}")
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

    def check(self, stat: dict):
        for key in stat.keys():
            if key in self.listen_map:
                self.listen_map[key]["checked"] = True

        for key, value in self.listen_map.items():
            if not value["checked"]:
                name = value["name"]
                protocol = value["protocol"]
                port = value["port"]
                self.critical(name, f"is not listening at {protocol}:{port}")


class DockerRule(Rule):
    def __init__(self, name: str = "docker", debug: bool = False):
        super().__init__(name, debug)
        self.docker_url = docker_url
        self.docker_watch_containers = docker_watch_containers

    def stat(self):
        docker_stat = {}
        if self.docker_watch_containers is None or len(self.docker_watch_containers) == 0:
            return docker_stat

        if isinstance(self.docker_url, str) and self.docker_url != "":
            client = docker.DockerClient(base_url=self.docker_url)
        else:
            client = docker.from_env()

        for container in client.containers.list(all=True):
            container_name = container.name
            container_status = container.status
            docker_stat[container_name] = container_status
        return docker_stat

    def check(self, stat: dict):
        if self.docker_watch_containers is None or len(self.docker_watch_containers) == 0:
            return

        for container_name in self.docker_watch_containers:
            try:
                container_status = stat[container_name].lower()
                if "up" not in container_status and "run" not in container_status and "healthy" not in container_status:
                    self.critical(container_name, f"wrong status ({container_status})")
            except KeyError:
                self.critical(container_name, "container not found")
