# ===== global settings =====
debug = True                    # enable debug mode
host = "localhost"              # the node's name
interval = 0                    # collect information periodically (in seconds)

# ===== monitor settings =====
cpu_load_warn = 0.7             # warning CPU load, >= 70%
cpu_load_critical = 0.95        # critical CPU load, >= 95%
cpu_interval = 1                # measure CPU load within 1 second(s)

mem_load_warn = 0.7             # warning memory usage, >= 70%
mem_load_critical = 0.95        # critical memory usage, >= 95%

disk_load_warn = 0.7            # warning disk usage, >= 70%
disk_load_critical = 0.9        # critical disk usage, >= 90%
disk_filter = None              # collect information on selected disks, e.g., disk_filter = ["/dev/sdc"]

net_conn_warn = 30000           # warning number of net connections, >= 30000
net_conn_critical = 50000       # critical number of net connections, >= 50000

net_send_warn = 200             # warning network send rate, >= 200 Mbps
net_recv_warn = 200             # warning network recv rate, >= 200 Mbps
net_bps_critical = 800          # critical network rate, >= 800 Mbps
net_send_packet_warn = 5000     # warning network send rate, >= 5000 pps
net_recv_packet_warn = 5000     # warning network recv rate, >= 5000 pps
net_pps_critical = 7000         # critical network send rate, >= 7000 pps
net_filter = None               # collect information only on selected nic(s), e.g., net_filter = ["lo", "eth0"]
net_interval = 1                # collect network information within 1 second(s)

temp_cpu_warn = 70              # warning CPU temperature, >= 70 Celsius
temp_disk_warn = 40             # warning disk temperature, >= 40 Celsius
temp_warn_percent = 0.7         # warning misc temperature, >= 70% critical temperature (if exists)
temp_cpu_critical = 80          # critical CPU temperature, >= 80 Celsius
temp_disk_critical = 50         # warning disk temperature, >= 50 Celsius
temp_critical_percent = 0.8     # warning misc temperature, >= 80% critical temperature (if exists)


listen_map = []                 # watch listen TCP/UDP sockets, e.g., listen_map = [("dns", "udp", 53)]

# ===== notify settings =====
log_file = 'sml.log'            # log notifier, enabled if the filename is specified
log_interval = 7                # enable log rotating, single log file for 7 days
log_reserve = 26                # maximized rotating log files

mail_from = ""                  # mail notifier, enabled if mail_from is specified
mail_password = ""              # SMTP authentication password
mail_smtp = ""                  # SMTP server domain
mail_tls = True                 # SMTP with TLS (default port 465)
mail_to = [""]                  # SMTP receiver list

tg_server = ""                  # tg bot notifier, enabled if bot relay server is specified
tg_secret = ""                  # tg bot secret, see https://gist.github.com/ertuil/6105c5888fffcb6bc548ffbb2a0560e5
