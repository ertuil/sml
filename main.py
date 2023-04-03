import platform
import traceback
from config import host, debug, log_file, mail_from, tg_server
from rules import CPURule, MemRule, DiskRule, NetRule, ListenRule, TempRule, get_current_time
from notify import LogNotifier, MailNotifier, TgNotifier


def main():
    all_rules = [
        CPURule("cpu", debug),
        MemRule("mem", debug),
        DiskRule("disk", debug),
        NetRule("net", debug),
        ListenRule("listen", debug)
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
            traceback.print_exc(e)
            all_warning.insert(0, f"[{r.name}] critical: {e}")

    notifiers = [LogNotifier(name="stdio", host=host, debug=debug, log_file="")]
    if log_file is not None and log_file != "":
        notifiers.append(LogNotifier(debug=debug, host=host, log_file=log_file))

    if mail_from is not None and mail_from != "":
        notifiers.append(MailNotifier(debug=debug, host=host))
    if tg_server is not None and tg_server != "":
        notifiers.append(TgNotifier(debug=debug, host=host))

    for n in notifiers:
        n.emit(current_time, all_warning, all_states)


if __name__ == "__main__":
    main()
