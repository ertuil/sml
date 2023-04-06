# ===== global settings =====
debug = True                    # enable debug mode
host = ""                       # the node's name, default use the hostname
interval = 0                    # collect information periodically (in seconds)

# ===== monitor settings =====
cpu_load_warn = 0.72            # warning CPU load, >= 72%
cpu_load_critical = 0.90        # critical CPU load, >= 90%
cpu_interval = 5                # measure CPU load within 5 second(s)

mem_load_warn = 0.72            # warning memory usage, >= 72%
mem_load_critical = 0.90        # critical memory usage, >= 90%

fs_usage_warn = 0.72            # warning filesystem usage, >= 72%
fs_usage_critical = 0.9         # critical filesystem usage, >= 90%
fs_filter = None                # collect information on selected filesystem, e.g., fs_filter = ["/dev/sda1"]

disk_read_warn = 100            # warning disk read rate, >= 100 Mbps (default value for SATA HDD)
disk_write_warn = 100           # warning disk write rate, >= 100 Mbps
disk_read_critical = 125        # critical disk read rate, >= 125 Mbps
disk_write_critical = 125       # critical disk write rate, >= 125 Mbps
disk_iops_warn = 1440           # warning disk iops, >= 1440 iops
disk_iops_critical = 1800       # critical disk iops, >= 1800 iops
disk_usage_warn = 0.55          # warning disk busy time, >= 56%
disk_usage_critical = 0.70      # critical disk busy time, >= 70%
disk_filter = None              # collect information on selected disk, e.g., fs_filter = ["/dev/sda"]
disk_interval = 5               # collect network information within 5 second(s)

net_conn_warn = 5000            # warning number of net connections, >= 5000
net_conn_critical = 10000       # critical number of net connections, >= 10000

net_io_warn = 0.72              # warning network send rate, >= 72% max bandwidth (default 1Gbps)
net_io_critical = 0.9           # critical network rate, >= 90% max bandwidth
net_pps_warn = 60000            # warning network send rate, >= 60000 pps
net_pps_critical = 80000        # critical network send rate, >= 80000 pps
net_filter = None               # collect information only on selected nic(s), e.g., net_filter = ["lo", "eth0"]
net_interval = 5                # collect network information within 5 second(s)
net_max_bandwidth = 1000        # network max bandwidth, 1000 Mbps

temp_cpu_warn = 70              # warning CPU temperature, >= 70 Celsius
temp_disk_warn = 40             # warning disk temperature, >= 40 Celsius
temp_warn_percent = 0.72        # warning misc temperature, >= 72% critical temperature (if exists)
temp_cpu_critical = 80          # critical CPU temperature, >= 80 Celsius
temp_disk_critical = 50         # warning disk temperature, >= 50 Celsius
temp_critical_percent = 0.9     # warning misc temperature, >= 90% critical temperature (if exists)


listen_map = []                 # watch listen TCP/UDP sockets, e.g., listen_map = [("dns", "udp", 53)]

docker_url = ""                 # docker daemon, leave empty to use automatic configure
docker_watch_containers = None  # watch the status of the containers


# ===== notify settings =====
log_file = 'sml.log'            # log notifier, enabled if the filename is specified
log_interval = 7                # enable log rotating, single log file for 7 days
log_reserve = 26                # maximized rotating log files

mail_from = ""                  # mail notifier, enabled if mail_from is specified
mail_password = ""              # SMTP authentication password
mail_smtp = ""                  # SMTP server domain
mail_tls = True                 # SMTP with TLS (default port 465)
mail_to = [""]                  # SMTP receiver list


# telegram bot relay server (for China mainland)
# see https://gist.github.com/ertuil/6105c5888fffcb6bc548ffbb2a0560e5
tg_server = ""                  # tg bot notifier, enabled if bot relay server is specified
tg_secret = ""                  # tg relay server bot secret

# telegram original API
tg_botid = ""                   # telegram bot id
tg_chatid = ""                  # telegram chat id
