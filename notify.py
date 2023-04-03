import logging
from typing import List
from email.mime.text import MIMEText
from email.header import Header
from smtplib import SMTP_SSL, SMTP
import requests

from config import mail_from, mail_password, mail_tls, mail_smtp, mail_to,\
                   tg_server, tg_secret, log_interval, log_reserve


class Notifier():
    def __init__(self, name: str = "", host: str = "", debug: bool = False):
        self.name = name
        self.host = host
        self.debug = debug

    def emit(self, current_time: str, warn_msgs: List[str], stat: any):
        pass


class LogNotifier(Notifier):
    def __init__(self, name: str = "log", host: str = "", debug: bool = False, log_file: str = ""):
        super().__init__(name=name, host=host, debug=debug)
        self.log_file = log_file
        self.log_interval = log_interval
        self.log_reserve = log_reserve if log_reserve is None or log_reserve <= 0 else 1

        logger = logging.getLogger(f"sml-{name}")
        if debug:
            logger.setLevel(logging.DEBUG)
        if self.log_file is None or self.log_file == "":
            fh = logging.StreamHandler()
        elif self.log_interval is not None and self.log_interval > 0:
            from logging import handlers
            fh = handlers.TimedRotatingFileHandler(self.log_file, when="D", interval=self.log_interval,
                                                   backupCount=self.log_reserve, encoding="utf-8")
        else:
            fh = logging.FileHandler(log_file, "a", encoding="utf-8")
        LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
        DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
        fm = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)
        fh.setFormatter(fm)
        logger.addHandler(fh)
        self.logger = logger

    def emit(self, current_time: str, warn_msgs: List[str], stat: any):
        self.logger.info("===== report information ====")
        self.logger.info(f"host: {self.host}")
        self.logger.info(f"time: {current_time}")
        for msg in warn_msgs:
            if "critical" in msg:
                self.logger.critical(msg)
            else:
                self.logger.warning(msg)
        if stat is not None:
            self.logger.debug("===== debug information ====")
            self.logger.debug(f"time: {current_time}")
            for rule_name, s in stat.items():
                self.logger.debug(f"[{rule_name}] {s}")


class MailNotifier(Notifier):
    def __init__(self, name: str = "mail", host: str = "", debug: bool = False):
        super().__init__(name=name, host=host, debug=debug)
        self.mail_from = mail_from
        self.mail_to = mail_to
        self.mail_smtp = mail_smtp
        self.mail_pass = mail_password
        self.mail_tls = mail_tls

    def emit(self, current_time: str, warn_msgs: List[str], stat: any):

        if warn_msgs is None or len(warn_msgs) == 0:
            return

        sender = SMTP(self.mail_smtp)
        if self.mail_tls:
            sender = SMTP_SSL(self.mail_smtp)
        if not self.debug:
            sender.set_debuglevel(0)

        sender.ehlo(self.mail_smtp)
        sender.login(self.mail_from, self.mail_pass)

        mail_msgs = [f"Host:\n{self.host}", f"Time:\n{current_time}"]
        mail_title = f"sml report - {self.host} - {current_time}"

        has_critical = False
        for msg in warn_msgs:
            if "critical" in msg:
                if not has_critical:
                    mail_msgs.append("\nCritical:")
                    has_critical = True
                mail_msgs.append(msg)

        mail_msgs.append("\nWarning:")
        for msg in warn_msgs:
            if "critical" not in msg:
                mail_msgs.append(msg)

        if stat is not None:
            mail_msgs.append("\nDebug:")
            for rule_name, s in stat.items():
                mail_msgs.append(f"[{rule_name}] {s}")

        message = "\r\n".join(mail_msgs)
        msg = MIMEText(message, "plain", 'utf-8')
        msg["Subject"] = Header(mail_title, 'utf-8')
        msg["From"] = mail_from
        msg["To"] = ",".join(mail_to)

        sender.sendmail(mail_from, mail_to, msg.as_string())
        sender.quit()


class TgNotifier(Notifier):
    def __init__(self, name: str = "tg", host: str = "", debug: bool = False):
        super().__init__(name=name, host=host, debug=debug)
        self.tg_server = tg_server
        self.tg_secret = tg_secret

    def emit(self, current_time: str, warn_msgs: List[str], stat: any):

        if warn_msgs is None or len(warn_msgs) == 0:
            return

        tg_msgs = [f"sml report - {self.host} - {current_time}", f"Host:\n{self.host}", f"Time:\n{current_time}"]

        has_critical = False
        for msg in warn_msgs:
            if "critical" in msg:
                if not has_critical:
                    tg_msgs.append("\nCritical:")
                    has_critical = True
                tg_msgs.append(msg)

        tg_msgs.append("\nWarning:")
        for msg in warn_msgs:
            if "critical" not in msg:
                tg_msgs.append(msg)

        if stat is not None:
            tg_msgs.append("\nDebug:")
            for rule_name, s in stat.items():
                tg_msgs.append(f"[{rule_name}] {s}")

        message = "\n".join(tg_msgs)
        requests.post(self.tg_server, data={"secret": self.tg_secret, "message": message})
