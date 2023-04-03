# ===== global settings =====
debug = True
host = "localhost"

# ===== monitor settings =====
cpu_load_warn = 0.7
cpu_load_critical = 0.95
cpu_interval = 1  # measure in ? second(s)

mem_load_warn = 0.7
mem_load_critical = 0.95

disk_load_warn = 0.7
disk_load_critical = 0.9
disk_filter = None
# disk_filter = ["/dev/sdc"]

net_send_warn = 200  # in Mbps
net_recv_warn = 200  # in Mbps
net_bps_critical = 800  # in Mbps
net_send_packet_warn = 5000  # in pps
net_recv_packet_warn = 5000  # in pps
net_pps_critical = 7000  # in pps
# net_filter = None
net_filter = ["lo", "eth0"]
net_interval = 1  # measure in ? second(s)

temp_cpu_warn = 70
temp_disk_warn = 40
temp_warn_percent = 0.7
temp_cpu_critical = 80
temp_disk_critical = 50
temp_critical_percent = 0.8


listen_map = []
# listen_map = [("dns", "udp", 53)]

# ===== notify settings =====
log_file = 'sml.log'

mail_from = ""
mail_password = ""
mail_smtp = ""
mail_tls = True
mail_to = [""]

tg_server = ""
tg_secret = ""
