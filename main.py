import os
import sys
import io
import json
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
        "INTERVAL": int(os.environ.get("INTERVAL", "60")),
        "HEALTHCHECKS_SLUG": os.environ.get("HEALTHCHECKS_SLUG")
    }
    if os.environ.get("LOG_LEVEL"):
        req_log_level = os.environ.get("LOG_LEVEL")
        if hasattr(logging, req_log_level):
            env["LOG_LEVEL"] = getattr(logging, req_log_level)
    return env

def get_logger(env):
    """
    Initializes logging /andler
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

def get_unbound_status(env, logger):
    """
    Retrieves current status of unbound service
    """
    uri = f"{env['OPNSENSE_HOST_SCHEMA']}://{env['OPNSENSE_HOST']}:{env['OPNSENSE_HOST_PORT']}/api/unbound/service/status"
    try:
        response = requests.get(uri, headers=get_auth(env), verify=env["VERIFY_SSL"], timeout=60)
        return response
    except requests.exceptions.ConnectionError:
        logger.error("failed to get Unbound status, cannot connect to OPNSense %s", uri)

def start_unbound_service(env, logger):
    """
    Attempts to start unbound service
    """
    uri = f"{env['OPNSENSE_HOST_SCHEMA']}://{env['OPNSENSE_HOST']}:{env['OPNSENSE_HOST_PORT']}/api/unbound/service/start"
    try:
        response = requests.post(uri, headers=get_auth(env), verify=env["VERIFY_SSL"], timeout=60)
        ping_healthchecks(env, "log", f"Started Unbound Service: {response}")
        return response
    except requests.exceptions.ConnectionError:
        logger.error("failed to start Unbound service, cannot connect to OPNSense %s", uri)

def stop_unbound_service(env, logger):
    """
    Attempts to stop unbound service
    """
    uri = f"{env['OPNSENSE_HOST_SCHEMA']}://{env['OPNSENSE_HOST']}:{env['OPNSENSE_HOST_PORT']}/api/unbound/service/stop"
    try:
        response = requests.post(uri, headers=get_auth(env), verify=env["VERIFY_SSL"], timeout=60)
        ping_healthchecks(env, "log", f"Stopped Unbound Service: {response}")
        return response
    except requests.exceptions.ConnectionError:
        logger.error("failed to stop Unbound service, cannot connect to OPNSense %s", uri)

def restart_unbound_service(env, logger):
    """
    Attempts to restart unbound service
    """
    uri = f"{env['OPNSENSE_HOST_SCHEMA']}://{env['OPNSENSE_HOST']}:{env['OPNSENSE_HOST_PORT']}/api/unbound/service/restart"
    try:
        response = requests.post(uri, headers=get_auth(env), verify=env["VERIFY_SSL"], timeout=60)
        ping_healthchecks(env, "log", f"Restarted Unbound Service: {response}")
        return response
    except requests.exceptions.ConnectionError:
        logger.error("failed to restart Unbound service, cannot connect to OPNSense %s", uri)

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

def ensure_unbound_service(env, logger):
    """
    Ensures Unbound is running
    """
    unbound_status = get_unbound_status(env, logger)
    if not unbound_status:
        logger.error("Failed to get unbound status")
        return
    while unbound_status.json().get("status") != "running":
        logger.error("Unbound not in running status, in status: %s", unbound_status.json().get("status"))
        start_unbound_service(env, logger)
        unbound_status = get_unbound_status(env)
        time.sleep(1)

def ensure_unbound_function(env, logger):
    """
    Attempts resolution of hosts and restarts Unbound service if necessary
    """
    captured_output = io.StringIO()
    captured_output_handler = logging.StreamHandler(captured_output)
    logger.addHandler(captured_output_handler)
    attempt_number = 0
    success = False
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
            restart_unbound_service(env, logger)
        else:
            success = True
            break
        attempt_number += 1

    ping_healthchecks(env, 'success', captured_output.getvalue(), success)
    logger.removeHandler(captured_output_handler)
    return success

def start_stdout_capture():
    """
    Starts capturing STDOUT output, returns buffer
    """
    captured_output = io.StringIO()
    sys.stdout = captured_output
    return captured_output

def stop_stdout_capture():
    """
    Stops capturing STDOUT output
    """
    sys.stdout = sys.__stdout__

def ping_healthchecks(env, ping_type = 'success', ping_content = None, success = False):
    if not env.get("HEALTHCHECKS_SLUG"):
        return

    if ping_content is None:
        ping_content = {}
    if ping_type.lower() == "success":
        uri = f"{env['HEALTHCHECKS_SLUG']}"
        if not success:
            uri += "/fail"
    elif ping_type.lower() == "log":
        uri = f"{env['HEALTHCHECKS_SLUG']}/log"
    elif ping_type.lower() == "start":
        uri = f"{env['HEALTHCHECKS_SLUG']}/start"
    try:
        response = None
        if ping_content:
            response = requests.post(
                    uri,
                    data=json.dumps({"content": ping_content}),
                    headers={"Content-Type": "application/json"},
                    timeout=60)
        else:
            response = requests.get(
                    uri,
                    timeout=60)

        if response and response.status_code != 200:
            logger.error("failed to ping healthchecks: %s", response.content)
    except requests.exceptions.ConnectionError:
        logger.error("failed to post healthchecks update, could not connect to healthchecks SLUG %s", env["HEALTHCHECKS_SLUG"])

def main():
    env = get_env()
    logger = get_logger(env)
    logger.info("Starting OPNSense-Unbound-Monitor Service")
    while True:
        logger.info("Starting OPNSense-Unbound-Monitor Interval")
        ping_healthchecks(env, 'start')
        ensure_unbound_service(env, logger)
        function_status = ensure_unbound_function(env, logger)
        logger.info("Completed OPNSense-Unbound-Monitor Interval")
        time.sleep(env["INTERVAL"])

if __name__ == "__main__":
    main()
