import platform
import traceback
import threading
from config import host, debug, mail_from, tg_server, interval, tg_botid
from rules import CPURule, MemRule, FSRule, NetRule, ListenRule, TempRule,\
      ConnRule, DiskRule, DockerRule, Rule
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
        ConnRule("conn", debug),
        DockerRule("docker", debug)
    ]

    if platform.system() == "Linux":
        all_rules.append(TempRule("temp", debug))

    if len(all_rules) > 0 and not all_rules[0].is_root:
        print("Warning: sml is not running in the root(admin) mode")

    all_warning = []
    all_states = {}

    threads = []

    class ruleThread (threading.Thread):
        def __init__(self, rule: Rule, current_time: str):
            threading.Thread.__init__(self)
            self.rule = rule
            self.name = self.rule.name
            self.current_time = current_time

        def run(self):
            try:
                states, warn = self.rule.run(current_time)
                all_warning.extend(warn)
                all_states[self.rule.name] = states
            except Exception as e:
                traceback.print_exc()
                all_warning.insert(0, f"[{self.rule.name}] critical: {e}")

    current_time = get_current_time()
    for r in all_rules:
        rule_t = ruleThread(r, current_time)
        threads.append(rule_t)
        rule_t.start()

    for t in threads:
        t.join()

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
    notifiers = []

    if mail_from is not None and mail_from != "":
        notifiers.append(MailNotifier(debug=debug, host=host))

    if tg_server is not None and tg_server != "":
        notifiers.append(TgNotifier(debug=debug, host=host))
    elif tg_botid is not None and tg_botid != "":
        notifiers.append(TgNotifier(debug=debug, host=host))

    notifiers.append(LogNotifier(name="log", host=host, debug=debug))
    return notifiers


if __name__ == "__main__":
    if interval is not None and interval > 0:
        service()
    else:
        single()
