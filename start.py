#!/usr/bin/env -S python3 -u

import os
import subprocess
import time
import glob
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
from dotenv import load_dotenv
from copy import deepcopy
from datetime import datetime, timedelta
from termcolor import colored
from cfghelper.cert import generate_selfsigned_cert, getCertDomains, readCertificate, requestCert
from cfghelper.util import *
from cfghelper.yamlcfg import getDomainsFromDir, getYamlFilesInDir, loadYamlFile

def le_hook():
    if HOOK:
        #if not os.path.exists("/var/run/docker.sock"):
        #    raise RuntimeError("Error, /var/run/docker.sock socket is missing.")
        print(HOOK)
        subprocess.run(HOOK, shell=True)

def le_fixpermissions():
    if os.name == 'posix':
        print("[INFO] Fixing permissions")
        #subprocess.run(["chown", "-R", " ${CHMOD:-root:root}", CERT_DIR], shell=True)
        #subprocess.run(["find", CERT_DIR, "-type d", "-exec chmod 755 {} \;"], shell=True)
        #subprocess.run(["find", CERT_DIR, "-type f", "-exec chmod ${CHMOD:-644} {} \;"], shell=True)

        
def le_renew(domain_name, data: dict):
    domains = [f"{s}.{domain_name}" for s in data.get("subdomains", [])]
    domains += [domain_name]
    
    plugin = PLUGINS.get(PLUGIN)
        
    additional = "--staging" if STAGING or data.get("staging", False) else ""
    args = [plugin, 
            "-n",
            "--agree-tos", 
            "--renew-by-default", 
            "--text", 
            f"-m {EMAIL}"]
    if additional:
        args += [additional]
    requestCert(domains, args)
        
    le_fixpermissions()
    print()

def le_checkIfRenewRequired(domain_name: str, data: dict) -> bool:
    from cryptography.hazmat.backends import default_backend
    
    certfile = os.path.join(CERT_DIR, domain_name, "fullchain.pem")
    if os.path.exists(certfile) and os.path.isfile(certfile):
        print(f"Found file {certfile}, checking...")
        td = timedelta(days=EXP_LIMIT)
        try:
            cert = readCertificate(certfile)
        except:
            print(colored(f"ERROR: Could not read certificate {certfile}", "red"))
            return False
        
        print("Checking domains... ", end="")
        domains = getCertDomains(cert)
        domains.sort()
        required_domains = list(data.get("subdomains", {}).keys()) if data.get("subdomains", {}) else []
        required_domains += [domain_name]
        required_domains.sort()
        
        if not domains == required_domains:
            warn("FAIL")
            print("Domains have changed")
            print(f"Certificate: {domains}\nDemanded: {required_domains}")
            return True
        success("PASS")
        
        print("Checking expiration date... ", end="")
        if cert.not_valid_after < datetime.now():
            warn("FAIL")
            print(f"Certificate has run out")
            return True
        if cert.not_valid_after - td < datetime.now():
            warn("FAIL")
            print(f"Certificate runs out in less than {EXP_LIMIT} days")
            return True
        success("PASS")
        print("No renewal required\n")
        
        return False
    elif CHICKENEGG or data.get("chickenegg", False):
        print(f"Could not find {certfile}")
        print("Generating temporaray selfsigned certificate")
        generate_selfsigned_cert(domain_name, CERT_DIR, time_days=1)
    return True
    
def le_run():
    domains = {}
    if DOMAIN_DIR:
        domains = getDomainsFromDir(DOMAIN_DIR)
        if not domains:
            warn(f"WARNING: no domain configs found in {DOMAIN_DIR}")
        
    for d in DOMAINS:
        data = {}
        if SUBDOMAINS:
            if SUBDOMAINS_ONLY:
                for sd in SUBDOMAINS:
                    domains[sd] = {}
            else:
                data['subdomains'] = SUBDOMAINS.copy()
                domains[d] = data

    if not domains:
        warn("WARNING: no domains found")
        
    if CLEAN:
        for d in glob.glob(CERT_DIR + "/*/"):
            dirname = os.path.normpath(d).split(os.path.sep)[-1]
            if not domains.get(dirname):
                print(f"Found hanging directory {CERT_DIR}/{dirname}. Cleaning...")
                for root, dirs, files in os.walk(os.path.join(CERT_DIR, dirname), topdown=False):
                    for name in files:
                        os.remove(os.path.join(root, name))
                    for name in dirs:
                        os.rmdir(os.path.join(root, name))
                    os.rmdir(root)

    for k,v in domains.items():
        if le_checkIfRenewRequired(k, v):
            le_renew(k, v)
    le_hook()

def le_start():
    if DOMAIN_DIR and WATCH:
        event_handler = PatternMatchingEventHandler("*.(yml|yaml)", "", ignore_directories=True, case_sensitive=False)
        event_handler.on_any_event = lambda event: le_run()
        obs = Observer()
        obs.schedule(event_handler, DOMAIN_DIR)
        obs.start()

    try:
        while True:
            le_run()
            if ONCE:
                break
            time.sleep(60*CHECK_FREQ)
    except KeyboardInterrupt:
        pass
    finally:
        if DOMAIN_DIR and WATCH:
            obs.stop()
            obs.join()
            

if __name__ == "__main__":
    load_dotenv()
    EMAIL = os.getenv("EMAIL")
    DOMAINS = [i for i in os.getenv("DOMAINS", default="").split(",") if i]
    SUBDOMAINS = [i for i in os.getenv("SUBDOMAINS", default="").split(",") if i]
    SUBDOMAINS_ONLY = str2bool(os.getenv("SUBDOMAINS_ONLY", default=False))
    STAGING = str2bool(os.getenv("STAGING", default=False))
    PLUGIN = os.getenv("PLUGIN")
    DOMAIN_DIR = os.getenv("DOMAIN_DIR")
    CHICKENEGG = str2bool(os.getenv("CHICKENEGG", default=False))
    EXP_LIMIT = int(os.getenv("EXP_LIMIT", default=30))
    CHECK_FREQ = int(os.getenv("CHECK_FREQ", default=30))
    CERT_DIR = os.path.normpath("/etc/letsencrypt/live") #os.getenv("CERT_DIR", default="/etc/letsencrypt/live")
    HOOK = os.getenv("HOOK", default="")
    WATCH = str2bool(os.getenv("WATCH", default=False))
    CLEAN = str2bool(os.getenv("CLEAN", default=False))
    ONCE = str2bool(os.getenv("ONCE", default=False))

    PLUGINS = {
        'route53': '--dns-route53'
    }
    
    if not EMAIL:
        raise Exception("EMAIL variable not set")
    if not DOMAINS and not DOMAIN_DIR:
        raise Exception("Either DOMAINS or DOMAIN_DIR needs to be set")
    if not PLUGIN in PLUGINS:
        raise Exception("Invalid plugin")
        
    le_start()