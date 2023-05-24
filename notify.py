import logging
from typing import Dict, List
from email.mime.text import MIMEText
from email.header import Header
from smtplib import SMTP_SSL, SMTP
import requests
import socket
import traceback

from config import mail_from, mail_password, mail_tls, mail_smtp, mail_to, log_file,\
                   tg_server, tg_secret, log_interval, log_reserve, tg_botid, tg_chatid


class Notifier():
    def __init__(self, name: str = "", host: str = "", debug: bool = False):
        self.name = name
        self.host = host
        self.debug = debug

        if self.host is None or self.host == "":
            self.host = socket.gethostname()

    def emit(self, current_time: str, warn_msgs: List[Dict[str, str]], stat: any):
        pass


class LogNotifier(Notifier):
    def __init__(self, name: str = "log", host: str = "", debug: bool = False):
        super().__init__(name=name, host=host, debug=debug)

        self.log_file = log_file
        self.log_interval = log_interval
        self.log_reserve = log_reserve if log_reserve is None or log_reserve <= 0 else 1

        logger = logging.getLogger(f"sml-{name}")
        if debug:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)

        LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
        DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
        fm = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)

        sh = logging.StreamHandler()
        sh.setFormatter(fm)
        logger.addHandler(sh)

        if self.log_file is not None and self.log_file != "":
            if self.log_interval is not None and self.log_interval > 0:
                from logging import handlers
                fh = handlers.TimedRotatingFileHandler(self.log_file, when="D", interval=self.log_interval,
                                                       backupCount=self.log_reserve, encoding="utf-8")
            else:
                fh = logging.FileHandler(log_file, "a", encoding="utf-8")
            fh.setFormatter(fm)
            logger.addHandler(fh)
        self.logger = logger

    def emit(self, current_time: str, warn_msgs: List[Dict[str, str]], stat: any):
        self.logger.info("===== report information ====")
        self.logger.info(f"host: {self.host}")
        self.logger.info(f"time: {current_time}")
        for msg in warn_msgs:
            if msg["level"] == "critical":
                self.logger.critical(msg["msg"])
            elif msg["level"] == "warning":
                self.logger.warn(msg["msg"])
            elif msg["level"] == "info":
                self.logger.info(msg["msg"])
        if self.debug:
            self.logger.debug("===== debug information ====")
            self.logger.debug(f"time: {current_time}")
            for msg in warn_msgs:
                if msg["level"] == "debug":
                    self.logger.debug(msg["msg"])


class MailNotifier(Notifier):
    def __init__(self, name: str = "mail", host: str = "", debug: bool = False):
        super().__init__(name=name, host=host, debug=debug)
        self.mail_from = mail_from
        self.mail_to = mail_to
        self.mail_smtp = mail_smtp
        self.mail_pass = mail_password
        self.mail_tls = mail_tls

    def emit(self, current_time: str, warn_msgs: List[Dict[str, str]], stat: any):

        need_emit = False

        mail_msgs = [f"Host:\n{self.host}", f"Time:\n{current_time}"]
        mail_title = f"sml report - {self.host} - {current_time}"

        has_critical = False
        for msg in warn_msgs:
            if msg["level"] == "critical":
                if not has_critical:
                    mail_msgs.append("\nCritical:")
                    has_critical = True
                mail_msgs.append(msg["msg"])
                if not need_emit:
                    need_emit = True

        has_warn = False
        for msg in warn_msgs:
            if msg["level"] == "warning":
                if not has_warn:
                    mail_msgs.append("\nWarning:")
                    has_warn = True
                mail_msgs.append(msg["msg"])
                if not need_emit:
                    need_emit = True

        has_info = False
        for msg in warn_msgs:
            if msg["level"] == "info":
                if not has_info:
                    mail_msgs.append("\nInfo:")
                    has_info = True
                mail_msgs.append(msg["msg"])
                if not need_emit:
                    need_emit = True

        if not need_emit:
            return

        if self.debug:
            mail_msgs.append("\nDebug:")
            for msg in warn_msgs:
                if msg["level"] == "debug":
                    mail_msgs.append(msg["msg"])

        if self.mail_tls:
            sender = SMTP_SSL(self.mail_smtp)
        else:
            sender = SMTP(self.mail_smtp)
        if not self.debug:
            sender.set_debuglevel(0)

        sender.ehlo(self.mail_smtp)
        sender.login(self.mail_from, self.mail_pass)

        try:
            message = "\r\n".join(mail_msgs)
            msg = MIMEText(message, "plain", 'utf-8')
            msg["Subject"] = Header(mail_title, 'utf-8')
            msg["From"] = mail_from
            msg["To"] = ",".join(mail_to)

            sender.sendmail(mail_from, mail_to, msg.as_string())
            sender.quit()
        except Exception as e:
            if self.debug:
                traceback.print_exc()
            warn_msgs.append({"level": "critical", "msg": f"send mail failed ({e})"})


class TgNotifier(Notifier):
    def __init__(self, name: str = "tg", host: str = "", debug: bool = False):
        super().__init__(name=name, host=host, debug=debug)
        self.tg_server = tg_server
        self.tg_secret = tg_secret
        self.tg_chatid = tg_chatid
        self.tg_botid = tg_botid

        if self.tg_server is not None and self.tg_server != "":
            self.relay = True
        elif self.tg_chatid != "" and self.tg_botid != "":
            self.relay = False
        else:
            raise Exception("sml: either tg_chatid or tg_server needs to be determined")

    def tg_send_msg(self, msg_list, warn_msgs):

        total = len(msg_list)
        idx = 0
        wait_msg_list = []
        wait_msg_len = 0
        self.failed = False
        while idx < total:
            current_msg = msg_list[idx]
            if len(current_msg) >= 1020:
                current_msg = current_msg[:1020] + "..."

            if wait_msg_len + len(current_msg) <= 2048:
                wait_msg_list.append(current_msg)
                wait_msg_len += (len(current_msg) + 1)
                idx += 1
            else:
                msg = "\n".join(wait_msg_list)
                self._tg_send_core(msg, warn_msgs)
                wait_msg_list.clear()
                wait_msg_len = 0
        if wait_msg_len > 0:
            msg = "\n".join(wait_msg_list)
            self._tg_send_core(msg, warn_msgs)

    def _tg_send_core(self, msg, warn_msgs):
        try:
            if self.relay:
                header = {"Content-Type": "application/json", "Authorization": f"Bearer {self.tg_secret}"}
                requests.post(self.tg_server, json={"msg": msg}, headers=header)\
                    .raise_for_status()
            else:
                url = "https://api.telegram.org/bot" + tg_botid + "/sendMessage"
                data = {"chat_id": self.tg_chatid, "text": msg}
                requests.post(url, data=data, timeout=10).raise_for_status()
        except Exception as e:
            if self.debug:
                traceback.print_exc()
            if not self.failed:
                warn_msgs.append({"level": "critical", "msg": f"send telegram message failed ({e})"})
                self.failed = True

    def emit(self, current_time: str, warn_msgs: List[str], stat: any):

        need_emit = False

        tg_msgs = [f"sml report - {self.host} - {current_time}", f"Host:\n{self.host}", f"Time:\n{current_time}"]

        has_critical = False
        for msg in warn_msgs:
            if msg["level"] == "critical":
                if not has_critical:
                    tg_msgs.append("\nCritical:")
                    has_critical = True
                tg_msgs.append(msg["msg"])
                if not need_emit:
                    need_emit = True

        has_warn = False
        for msg in warn_msgs:
            if msg["level"] == "warning":
                if not has_warn:
                    tg_msgs.append("\nWarning:")
                    has_warn = True
                tg_msgs.append(msg["msg"])
                if not need_emit:
                    need_emit = True

        has_info = False
        for msg in warn_msgs:
            if msg["level"] == "info":
                if not has_info:
                    tg_msgs.append("\nInfo:")
                    has_info = True
                tg_msgs.append(msg["msg"])
                if not need_emit:
                    need_emit = True

        if not need_emit:
            return

        if self.debug:
            tg_msgs.append("\nDebug:")
            for msg in warn_msgs:
                if msg["level"] == "debug":
                    tg_msgs.append(msg["msg"])
        self.tg_send_msg(tg_msgs, warn_msgs)
