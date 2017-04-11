import re
import smtplib
import logging
import socket

try:
    raw_input
except NameError:
    def raw_input(prompt=''):
        return input(prompt)

try:
    import DNS
    ServerError = DNS.ServerError
    DNS.DiscoverNameServers()
except (ImportError, AttributeError):
    DNS = None

    class ServerError(Exception):
        pass                                       

email_regex = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")

MX_DNS_CACHE = {}
MX_CHECK_CACHE = {}


def get_mx_ip(hostname):
    if hostname not in MX_DNS_CACHE:
        try:
            MX_DNS_CACHE[hostname] = DNS.mxlookup(hostname)
        except ServerError as e:
            if e.rcode == 3 or e.rcode == 2:  
                MX_DNS_CACHE[hostname] = None
            else:
                raise

    return MX_DNS_CACHE[hostname]


def validate_email(email, check_mx=False, verify=False, debug=False, smtp_timeout=10):

    if debug:
        logger = logging.getLogger('validate_email')
        logger.setLevel(logging.DEBUG)
    else:
        logger = None

    try:
        assert re.match(email_regex, email) is not None
        check_mx |= verify
        if check_mx:
            if not DNS:
                raise Exception('To check mx records or to check if the email exists you must,'
                                'have installed pyDNS python package')
            hostname = email[email.find('@') + 1:]
            mx_hosts = get_mx_ip(hostname)
            if mx_hosts is None:
                return False
            for mx in mx_hosts:
                try:
                    if not verify and mx[1] in MX_CHECK_CACHE:
                        return MX_CHECK_CACHE[mx[1]]
                    smtp = smtplib.SMTP(timeout=smtp_timeout)
                    smtp.connect(mx[1])
                    MX_CHECK_CACHE[mx[1]] = True
                    if not verify:
                        try:
                            smtp.quit()
                        except smtplib.SMTPServerDisconnected:
                            pass
                        return True
                    status, _ = smtp.helo()
                    if status != 250:
                        smtp.quit()
                        if debug:
                            logger.debug(u'%s answer: %s - %s', mx[1], status, _)
                        continue
                    smtp.mail('')
                    status, _ = smtp.rcpt(email)
                    if status == 250:
                        smtp.quit()
                        return True
                    if debug:
                        logger.debug(u'%s answer: %s - %s', mx[1], status, _)
                    smtp.quit()
                except smtplib.SMTPServerDisconnected:  # Server not permits verify user
                    if debug:
                        logger.debug(u'%s disconected.', mx[1])
                except smtplib.SMTPConnectError:
                    if debug:
                        logger.debug(u'Unable to connect to %s.', mx[1])
            return None
    except AssertionError:
        return False
    except (ServerError, socket.error) as e:
        if debug:
            logger.debug('ServerError or socket.error exception raised (%s).', e)
        return None
    return True

if __name__ == "__main__":
    import time
    while True:
        email = raw_input('Enter email for validation: ')


        logging.basicConfig()

        result = validate_email(email, debug=True, smtp_timeout=1)
        if result:
            print("Valid!")
        elif result is None:
            print("I'm not sure.")
        else:
            print("Invalid!")

        time.sleep(1)
