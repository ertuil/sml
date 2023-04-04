import platform
import traceback
from config import host, debug, log_file, mail_from, tg_server, interval
from rules import CPURule, MemRule, FSRule, NetRule, ListenRule, TempRule, ConnRule, DiskRule
from notify import LogNotifier, MailNotifier, TgNotifier
from utils import get_current_time


def fire():
    all_rules = [
        CPURule("cpu", debug),
        MemRule("mem", debug),
        FSRule("fs", debug),
        DiskRule("disk", debug),
        NetRule("net", debug),
        ListenRule("listen", debug),
        ConnRule("conn", debug)
    ]

    if platform.system() == "Linux":
        all_rules.append(TempRule("temperature", debug))

    all_warning = []
    all_states = {}
    current_time = get_current_time()
    for r in all_rules:
        try:
            states, warn = r.run(current_time)
            all_warning.extend(warn)
            all_states[r.name] = states
        except Exception as e:
            traceback.print_exc()
            all_warning.insert(0, f"[{r.name}] critical: {e}")

    return current_time, all_warning, all_states


def service():
    notifiers = init_notifiers()

    def warp_single(notifiers=None):
        print(f"start sml at {get_current_time()}")
        single(notifiers)
        timer = threading.Timer(interval=interval, function=warp_single, args=[notifiers])
        timer.start()

    def warp_bye():
        print("exit sml")

    import threading
    import atexit
    timer = threading.Timer(interval=interval, function=warp_single, args=[notifiers])
    timer.start()
    atexit.register(warp_bye)


def single(notifiers=None):
    if notifiers is None:
        notifiers = init_notifiers()
    current_time, all_warning, all_states = fire()
    for n in notifiers:
        n.emit(current_time, all_warning, all_states)


def init_notifiers():
    notifiers = [LogNotifier(name="stdio", host=host, debug=debug, log_file="")]
    if log_file is not None and log_file != "":
        notifiers.append(LogNotifier(debug=debug, host=host, log_file=log_file))

    if mail_from is not None and mail_from != "":
        notifiers.append(MailNotifier(debug=debug, host=host))
    if tg_server is not None and tg_server != "":
        notifiers.append(TgNotifier(debug=debug, host=host))
    return notifiers


if __name__ == "__main__":
    if interval is not None and interval > 0:
        service()
    else:
        single()
