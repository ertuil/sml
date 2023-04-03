import time


def get_current_time():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _byte_value(n):
    symbols = ('K', 'M', 'G', 'T', 'P', 'E')
    prefix = {}
    for i, k in enumerate(symbols):
        prefix[k] = 1 << (i+1) * 10
    for k in reversed(symbols):
        if n >= prefix[k]:
            value = float(n) / prefix[k]
            return '%.2f %s' % (value, k)
    return '%s B' % n


def _bps_value(n):
    symbols = ('Kbps', 'Mbps', 'Gbps', 'Tbps', 'Pbps', 'Ebps')
    prefix = {}
    for i, k in enumerate(symbols):
        prefix[k] = 1 << (i+1) * 10
    for k in reversed(symbols):
        if n >= prefix[k]:
            value = float(n) / prefix[k]
            return '%.2f %s' % (value, k)
    return '%s Bbps' % n


def _percent_value(x):
    return f"{x*100:.2f}%"
