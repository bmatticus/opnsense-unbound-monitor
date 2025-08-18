import os
import requests
import dns.resolver
from base64 import b64encode
import logging
import time

def get_env():
    """
    Attempts to gather environment variables for settings and returns a dictionary of values
    """
    env = {
        "OPNSENSE_KEY": os.environ.get("OPNSENSE_KEY"),
        "OPNSENSE_SECRET": os.environ.get("OPNSENSE_SECRET"),
        "OPNSENSE_HOST": os.environ.get("OPNSENSE_HOST"),
        "OPNSENSE_HOST_SCHEMA": os.environ.get("OPNSENSE_HOST_SCHEMA", "https"),
        "OPNSENSE_HOST_PORT": os.environ.get("OPNSENSE_HOST_PORT", "443"),
        "VERIFY_SSL": os.environ.get("VERIFY_SSL", "TRUE").upper() == "TRUE",
        "HOST_LIST": os.environ.get("HOST_LIST", "google.com,reddit.com").split(","),
        "LOG_LEVEL": logging.WARN,
        "MAX_ATTEMPTS": os.environ.get("MAX_ATTEMPTS", 1),
        "OPNSENSE_DNS_IP": os.environ.get("OPNSENSE_DNS_IP", os.environ.get("OPNSENSE_HOST")),
        "OPNSENSE_DNS_PORT": int(os.environ.get("OPNSENSE_DNS_PORT", "53")),
        "DNS_TIMEOUT": float(os.environ.get("DNS_TIMEOUT", "2.0")),
        "DNS_LIFETIME": float(os.environ.get("DNS_LIFETIME", "5.0")),
        "DNS_TCP": os.environ.get("DNS_TCP", "FALSE").upper() == "TRUE",
    }
    if os.environ.get("LOG_LEVEL"):
        req_log_level = os.environ.get("LOG_LEVEL")
        if hasattr(logging, req_log_level):
            env["LOG_LEVEL"] = getattr(logging, req_log_level)
    return env

def get_logger(env):
    """
    Initializes logging handler
    """
    logger = logging.getLogger(__name__)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(env["LOG_LEVEL"])
    return logger

def get_auth(env):
    """
    Returns Auth Header
    """
    auth = b64encode(f"{env['OPNSENSE_KEY']}:{env['OPNSENSE_SECRET']}".encode()).decode()
    return {"Authorization": f"Basic {auth}"}

def get_unbound_status(env):
    """
    Retrieves current status of unbound service
    """
    uri = f"{env['OPNSENSE_HOST_SCHEMA']}://{env['OPNSENSE_HOST']}:{env['OPNSENSE_HOST_PORT']}/api/unbound/service/status"
    response = requests.get(uri, headers=get_auth(env), verify=env["VERIFY_SSL"])
    return response

def start_unbound_service(env):
    """
    Attempts to start unbound service
    """
    uri = f"{env['OPNSENSE_HOST_SCHEMA']}://{env['OPNSENSE_HOST']}:{env['OPNSENSE_HOST_PORT']}/api/unbound/service/start"
    response = requests.post(uri, headers=get_auth(env), verify=env["VERIFY_SSL"])
    return response

def stop_unbound_service(env):
    """
    Attempts to stop unbound service
    """
    uri = f"{env['OPNSENSE_HOST_SCHEMA']}://{env['OPNSENSE_HOST']}:{env['OPNSENSE_HOST_PORT']}/api/unbound/service/stop"
    response = requests.post(uri, headers=get_auth(env), verify=env["VERIFY_SSL"])
    return response

def restart_unbound_service(env):
    """
    Attempts to restart unbound service
    """
    uri = f"{env['OPNSENSE_HOST_SCHEMA']}://{env['OPNSENSE_HOST']}:{env['OPNSENSE_HOST_PORT']}/api/unbound/service/restart"
    response = requests.post(uri, headers=get_auth(env), verify=env["VERIFY_SSL"])
    return response

def get_resolver(env, logger):
    """ 
    Sets up a dnspython resolve and ensures it is pointing at OPNSense where Unbound is runing
    """
    r = dns.resolver.Resolver(configure=False)  # don't read /etc/resolv.conf
    r.nameservers = [env["OPNSENSE_DNS_IP"]]
    r.port = env["OPNSENSE_DNS_PORT"]
    r.timeout = env["DNS_TIMEOUT"]     # per-try timeout
    r.lifetime = env["DNS_LIFETIME"]   # overall timeout across tries
    logger.info("Using Unbound at %s:%s", env["OPNSENSE_DNS_IP"], env["OPNSENSE_DNS_PORT"])
    return r

def resolve_host(host, logger, env):
    """
    Attempts to resolve test hosts
    """
    resolver = get_resolver(env, logger)
    try:
        return resolver.resolve(host, "A")
    except dns.resolver.NXDOMAIN:
        logger.error("NXDOMAIN FOR %s", host)
        return False
    except dns.resolver.NoAnswer:
        logger.error("NO ANSWER FOR %s", host)
        return False
    except dns.exception.DNSException as e:
        logger.error("DNS FAILURE FOR %s: %s", host, e)
        return False

def main():
    env = get_env()
    logger = get_logger(env)
    unbound_status = get_unbound_status(env)
    while unbound_status.json().get("status") != "running":
        logger.error("Unbound not in running status, in status: %s", unbound_status.json().get("status"))
        start_unbound_service(env)
        unbound_status = get_unbound_status(env)
        time.sleep(1)

    attempt_number = 0
    while attempt_number < env["MAX_ATTEMPTS"]:
        failure_count = 0
        for host in env.get("HOST_LIST"):
            res = resolve_host(host, logger, env)
            for answer in res:
                logger.info("Resolution for host %s: %s", host, answer)
            if not res:
                failure_count += 1
        if failure_count > 1:
            logger.error("Failure count of %s, attempting to restart Unbound", failure_count)
            restart_unbound_service(env)
        else:
            break
        attempt_number += 1

if __name__ == "__main__":
    main()
