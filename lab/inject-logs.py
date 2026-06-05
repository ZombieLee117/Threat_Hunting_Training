#!/usr/bin/env python3
"""
inject-logs.py
==============
Generates randomized training log events and injects them into
the Wazuh indexer so students hunt through fresh data every time.
 
All IoC values (IPs, usernames, filenames, timestamps, ports) are
randomly generated on each run — students cannot memorize answers
from the web trainer.
"""
 
import json
import random
import string
import time
import urllib3
import requests
from datetime import datetime, timedelta
 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
 
# ── Config ────────────────────────────────────────────────
INDEXER_URL  = "https://wazuh.indexer:9200"
INDEXER_USER = "admin"
INDEXER_PASS = "SecretPassword"
INDEX_NAME   = "wazuh-alerts-4.x-training"
 
# ── Randomizers ───────────────────────────────────────────
def rand_external_ip():
    """Generate a random external AWS-style IP"""
    blocks = [
        (3,  3),   (13, 13), (18, 18), (34, 35),
        (44, 44),  (52, 54), (99, 100)
    ]
    b = random.choice(blocks)
    return f"{random.randint(b[0],b[1])}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
 
def rand_internal_ip():
    return f"10.{random.randint(0,10)}.{random.randint(0,5)}.{random.randint(10,250)}"
 
def rand_username():
    first = random.choice(["jsmith","bwilson","mmartinez","ktaylor","dthompson",
                            "arobinson","cwhite","nharris","rjones","lbrown"])
    return first
 
def rand_domain():
    return random.choice(["CORP","ACME","NEXUS","INFRA","DEVNET"])
 
def rand_service_name():
    """4-letter random service name like YHZB"""
    return ''.join(random.choices(string.ascii_uppercase, k=4))
 
def rand_dropper_name():
    names = ["svchost32.exe","wmiprvse.exe","lsass32.exe","taskhost.exe",
             "spoolsv32.exe","csrss32.exe","dllhost32.exe","conhost32.exe"]
    return random.choice(names)
 
def rand_module_name():
    prefixes = ["mod_auth","mod_proxy","mod_cache","mod_filter","mod_rewrite"]
    suffixes = ["_fwd","_ext","_handler","_core","_hook"]
    return random.choice(prefixes) + random.choice(suffixes)
 
def rand_archive_name():
    names = ["backup","data","export","archive","collect","dump","files","docs"]
    return random.choice(names) + ".7z"
 
def rand_cred_file():
    names = ["tkn.txt","out.dat","pass.log","creds.tmp","hash.txt","dump.dat"]
    return random.choice(names)
 
def rand_port():
    ports = [4443, 7443, 8080, 8443, 9090, 9443, 10443, 11443]
    return random.choice(ports)
 
def rand_timestamp(base, offset_seconds):
    t = base + timedelta(seconds=offset_seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")
 
def rand_hash():
    return ''.join(random.choices(string.hexdigits.lower(), k=32))
 
# ── Build event sets ──────────────────────────────────────
def build_scenario_events():
    base_time = datetime.utcnow() - timedelta(hours=random.randint(2, 48))
    attacker_ip = rand_external_ip()
    wazuh_ip    = rand_internal_ip()
    user        = rand_username()
    domain      = rand_domain()
    svc_name    = rand_service_name()
    dropper     = rand_dropper_name()
    module      = rand_module_name()
    archive     = rand_archive_name()
    cred_file   = rand_cred_file()
    exfil_port  = rand_port()
    pipe_name   = f"\\pipe\\{svc_name}_{random.randint(1000,9999)}"
    dropper_path_desktop = f"C:\\Users\\{user}\\Desktop\\{dropper}"
    dropper_path_public  = f"C:\\Users\\Public\\{dropper}"
    doc_name    = f"Q{random.randint(1,4)}-{random.randint(2024,2025)}_Report.docx"
 
    events = []
    t = 0
 
    # ── Scenario 1: SSH Brute Force ───────────────────────
    fail_count = random.randint(8, 20)
    for i in range(fail_count):
        victim_user = random.choice(["root","admin","sysadmin","deploy","ubuntu","ec2-user"])
        events.append({
            "_index": INDEX_NAME,
            "_source": {
                "timestamp": rand_timestamp(base_time, t + i*2),
                "agent": {"name": "WEB-APP01", "id": "004", "ip": wazuh_ip},
                "rule": {
                    "id": "5710",
                    "level": 10,
                    "description": "sshd: brute force trying to get access to the system",
                    "groups": ["authentication_failed","attacks","syslog","sshd"]
                },
                "data": {"srcip": attacker_ip, "dstuser": victim_user, "srcport": str(random.randint(40000,65000))},
                "full_log": f"sshd[{random.randint(1000,9999)}]: Failed password for {victim_user} from {attacker_ip} port {random.randint(40000,65000)} ssh2"
            }
        })
    t += fail_count * 2 + random.randint(2,8)
 
    # Successful SSH login
    events.append({
        "_index": INDEX_NAME,
        "_source": {
            "timestamp": rand_timestamp(base_time, t),
            "agent": {"name": "WEB-APP01", "id": "004", "ip": wazuh_ip},
            "rule": {
                "id": "5715",
                "level": 3,
                "description": "sshd: authentication success",
                "groups": ["authentication_success","syslog","sshd"]
            },
            "data": {"srcip": attacker_ip, "dstuser": "deploy", "srcport": str(random.randint(40000,65000))},
            "full_log": f"sshd[{random.randint(1000,9999)}]: Accepted password for deploy from {attacker_ip} port {random.randint(40000,65000)} ssh2"
        }
    })
    t += random.randint(30, 120)
 
    # ── Scenario 2: Named Pipe Priv Esc ───────────────────
    # Sysmon Event 1 — dropper process created
    events.append({
        "_index": INDEX_NAME,
        "_source": {
            "timestamp": rand_timestamp(base_time, t),
            "agent": {"name": "WKS-RSCH01", "id": "003", "ip": rand_internal_ip()},
            "rule": {"id": "92100", "level": 12, "description": "Sysmon - Event 1: Process creation", "groups": ["sysmon"]},
            "data": {
                "win": {
                    "system": {"eventID": "1", "channel": "Microsoft-Windows-Sysmon/Operational"},
                    "eventdata": {
                        "image": dropper_path_desktop,
                        "parentImage": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                        "commandLine": dropper,
                        "user": f"{domain}\\{user}",
                        "hashes": f"SHA256={rand_hash()}"
                    }
                }
            }
        }
    })
    t += random.randint(3, 8)
 
    # Sysmon Event 11 — file dropped to Public
    events.append({
        "_index": INDEX_NAME,
        "_source": {
            "timestamp": rand_timestamp(base_time, t),
            "agent": {"name": "WKS-RSCH01", "id": "003", "ip": rand_internal_ip()},
            "rule": {"id": "92111", "level": 8, "description": "Sysmon - Event 11: FileCreate", "groups": ["sysmon"]},
            "data": {
                "win": {
                    "system": {"eventID": "11", "channel": "Microsoft-Windows-Sysmon/Operational"},
                    "eventdata": {
                        "image": dropper_path_desktop,
                        "targetFilename": dropper_path_public,
                        "user": f"{domain}\\{user}",
                        "creationUtcTime": rand_timestamp(base_time, t)
                    }
                }
            }
        }
    })
    t += random.randint(2, 10)
 
    # Sysmon Event 17 — pipe created
    events.append({
        "_index": INDEX_NAME,
        "_source": {
            "timestamp": rand_timestamp(base_time, t),
            "agent": {"name": "WKS-RSCH01", "id": "003", "ip": rand_internal_ip()},
            "rule": {"id": "92117", "level": 14, "description": "Sysmon - Event 17: Pipe Created (possible named pipe impersonation)", "groups": ["sysmon","privilege_escalation"]},
            "data": {
                "win": {
                    "system": {"eventID": "17", "channel": "Microsoft-Windows-Sysmon/Operational"},
                    "eventdata": {
                        "pipeName": pipe_name,
                        "image": dropper_path_public,
                        "user": f"{domain}\\{user}"
                    }
                }
            }
        }
    })
    t += 1
 
    # Sysmon Event 18 — pipe connected by SYSTEM
    events.append({
        "_index": INDEX_NAME,
        "_source": {
            "timestamp": rand_timestamp(base_time, t),
            "agent": {"name": "WKS-RSCH01", "id": "003", "ip": rand_internal_ip()},
            "rule": {"id": "92118", "level": 14, "description": "Sysmon - Event 18: Pipe Connected (SYSTEM process connected to suspicious pipe)", "groups": ["sysmon","privilege_escalation"]},
            "data": {
                "win": {
                    "system": {"eventID": "18", "channel": "Microsoft-Windows-Sysmon/Operational"},
                    "eventdata": {
                        "pipeName": pipe_name,
                        "image": "C:\\Windows\\System32\\services.exe",
                        "user": "NT AUTHORITY\\SYSTEM"
                    }
                }
            }
        }
    })
    t += random.randint(1, 3)
 
    # Sysmon Event 13 — registry persistence
    events.append({
        "_index": INDEX_NAME,
        "_source": {
            "timestamp": rand_timestamp(base_time, t),
            "agent": {"name": "WKS-RSCH01", "id": "003", "ip": rand_internal_ip()},
            "rule": {"id": "92113", "level": 12, "description": "Sysmon - Event 13: Registry value set (possible service persistence)", "groups": ["sysmon","persistence"]},
            "data": {
                "win": {
                    "system": {"eventID": "13", "channel": "Microsoft-Windows-Sysmon/Operational"},
                    "eventdata": {
                        "eventType": "SetValue",
                        "targetObject": f"HKLM\\System\\CurrentControlSet\\Services\\{svc_name}\\ImagePath",
                        "details": dropper_path_public,
                        "user": "NT AUTHORITY\\SYSTEM"
                    }
                }
            }
        }
    })
    t += random.randint(60, 300)
 
    # ── Scenario 3: Apache Rootkit ────────────────────────
    module_path = f"/etc/apache2/mods-enabled/{module}.so"
    cred_path   = f"/var/www/html/{cred_file}"
 
    # Linux audit — apxs execution
    events.append({
        "_index": INDEX_NAME,
        "_source": {
            "timestamp": rand_timestamp(base_time, t),
            "agent": {"name": "WEB-APP01", "id": "004", "ip": wazuh_ip},
            "rule": {"id": "80792", "level": 12, "description": "Audit: Command execution detected", "groups": ["audit","linux"]},
            "data": {
                "audit": {
                    "command": "apxs",
                    "execve": {"a0": "apxs", "a1": "-i", "a2": f"-a -c {module}.c"},
                    "auid": "deploy",
                    "pid": str(random.randint(10000, 39999))
                }
            }
        }
    })
    t += random.randint(5, 15)
 
    # FIM — new Apache module
    events.append({
        "_index": INDEX_NAME,
        "_source": {
            "timestamp": rand_timestamp(base_time, t),
            "agent": {"name": "WEB-APP01", "id": "004", "ip": wazuh_ip},
            "rule": {"id": "554", "level": 7, "description": "File added to the system", "groups": ["ossec","syscheck","syscheck_entry_added"]},
            "syscheck": {
                "path": module_path,
                "event": "added",
                "size_after": str(random.randint(40000, 65000)),
                "md5_after": rand_hash(),
                "sha256_after": rand_hash()
            }
        }
    })
    t += random.randint(5, 20)
 
    # FIM — credential harvest file
    events.append({
        "_index": INDEX_NAME,
        "_source": {
            "timestamp": rand_timestamp(base_time, t),
            "agent": {"name": "WEB-APP01", "id": "004", "ip": wazuh_ip},
            "rule": {"id": "554", "level": 7, "description": "File added to the system", "groups": ["ossec","syscheck","syscheck_entry_added"]},
            "syscheck": {
                "path": cred_path,
                "event": "added",
                "size_after": str(random.randint(800, 3000)),
                "md5_after": rand_hash(),
                "sha256_after": rand_hash()
            }
        }
    })
    t += random.randint(120, 600)
 
    # ── Scenario 4: Data Staging and Exfil ───────────────
    archive_path = f"C:\\Users\\Public\\{archive}"
    docs_path    = f"C:\\Users\\{user}\\Documents\\*"
 
    # Sysmon Event 1 — 7-Zip execution
    events.append({
        "_index": INDEX_NAME,
        "_source": {
            "timestamp": rand_timestamp(base_time, t),
            "agent": {"name": "WKS-RSCH01", "id": "003", "ip": rand_internal_ip()},
            "rule": {"id": "92100", "level": 8, "description": "Sysmon - Event 1: Process creation (archiving tool)", "groups": ["sysmon"]},
            "data": {
                "win": {
                    "system": {"eventID": "1", "channel": "Microsoft-Windows-Sysmon/Operational"},
                    "eventdata": {
                        "image": "C:\\Program Files\\7-Zip\\7z.exe",
                        "commandLine": f"7z.exe a -p {archive_path} {docs_path}",
                        "user": f"{domain}\\{user}",
                        "parentImage": dropper_path_public
                    }
                }
            }
        }
    })
    t += random.randint(2, 6)
 
    # Sysmon Event 11 — archive file created
    events.append({
        "_index": INDEX_NAME,
        "_source": {
            "timestamp": rand_timestamp(base_time, t),
            "agent": {"name": "WKS-RSCH01", "id": "003", "ip": rand_internal_ip()},
            "rule": {"id": "92111", "level": 8, "description": "Sysmon - Event 11: FileCreate (archive staged for exfil)", "groups": ["sysmon","exfiltration"]},
            "data": {
                "win": {
                    "system": {"eventID": "11", "channel": "Microsoft-Windows-Sysmon/Operational"},
                    "eventdata": {
                        "image": "C:\\Program Files\\7-Zip\\7z.exe",
                        "targetFilename": archive_path,
                        "creationUtcTime": rand_timestamp(base_time, t)
                    }
                }
            }
        }
    })
    t += random.randint(3, 8)
 
    # Sysmon Event 3 — outbound C2 connection
    events.append({
        "_index": INDEX_NAME,
        "_source": {
            "timestamp": rand_timestamp(base_time, t),
            "agent": {"name": "WKS-RSCH01", "id": "003", "ip": rand_internal_ip()},
            "rule": {"id": "92103", "level": 14, "description": "Sysmon - Event 3: Network connection to external IP (possible C2 exfiltration)", "groups": ["sysmon","exfiltration","network"]},
            "data": {
                "win": {
                    "system": {"eventID": "3", "channel": "Microsoft-Windows-Sysmon/Operational"},
                    "eventdata": {
                        "image": dropper_path_public,
                        "destinationIp": attacker_ip,
                        "destinationPort": str(exfil_port),
                        "protocol": "tcp",
                        "initiated": "true",
                        "user": f"{domain}\\{user}"
                    }
                }
            }
        }
    })
    t += random.randint(2, 5)
 
    # Sysmon Event 3 — 7-Zip sending archive
    events.append({
        "_index": INDEX_NAME,
        "_source": {
            "timestamp": rand_timestamp(base_time, t),
            "agent": {"name": "WKS-RSCH01", "id": "003", "ip": rand_internal_ip()},
            "rule": {"id": "92103", "level": 14, "description": "Sysmon - Event 3: Network connection (archive exfiltrated)", "groups": ["sysmon","exfiltration","network"]},
            "data": {
                "win": {
                    "system": {"eventID": "3", "channel": "Microsoft-Windows-Sysmon/Operational"},
                    "eventdata": {
                        "image": "C:\\Program Files\\7-Zip\\7z.exe",
                        "destinationIp": attacker_ip,
                        "destinationPort": str(exfil_port),
                        "protocol": "tcp",
                        "initiated": "true",
                        "user": f"{domain}\\{user}"
                    }
                }
            }
        }
    })
 
    return events, {
        "attacker_ip": attacker_ip,
        "user": user,
        "domain": domain,
        "service_name": svc_name,
        "dropper": dropper,
        "pipe_name": pipe_name,
        "module": f"{module}.so",
        "cred_file": cred_file,
        "archive": archive,
        "exfil_port": exfil_port
    }
 
 
# ── Inject into Wazuh Indexer ─────────────────────────────
def inject_events(events):
    print(f"\n[*] Injecting {len(events)} training events into Wazuh...")
    success = 0
    for ev in events:
        try:
            r = requests.post(
                f"{INDEXER_URL}/{ev['_index']}/_doc",
                json=ev["_source"],
                auth=(INDEXER_USER, INDEXER_PASS),
                verify=False,
                timeout=10
            )
            if r.status_code in (200, 201):
                success += 1
            else:
                print(f"  [!] Failed: {r.status_code} — {r.text[:100]}")
        except Exception as e:
            print(f"  [!] Error: {e}")
        time.sleep(0.05)
    print(f"[+] Injected {success}/{len(events)} events successfully.")
    return success
 
 
# ── Print summary for students ────────────────────────────
def print_summary(meta):
    print("\n" + "="*60)
    print("  TRAINING LAB READY")
    print("="*60)
    print(f"\n  Open Wazuh Dashboard: https://localhost")
    print(f"  Username: admin")
    print(f"  Password: SecretPassword")
    print("\n  This session's investigation targets:")
    print(f"  ├─ Attacker IP     : {meta['attacker_ip']}")
    print(f"  ├─ Compromised user: {meta['domain']}\\{meta['user']}")
    print(f"  ├─ Dropper binary  : {meta['dropper']}")
    print(f"  ├─ Service name    : {meta['service_name']}")
    print(f"  ├─ Pipe name       : {meta['pipe_name']}")
    print(f"  ├─ Apache module   : {meta['module']}")
    print(f"  ├─ Cred file       : {meta['cred_file']}")
    print(f"  ├─ Archive file    : {meta['archive']}")
    print(f"  └─ Exfil port      : {meta['exfil_port']}")
    print("\n  Use the web trainer to learn the KQL queries.")
    print("  Then hunt for these values in the real Wazuh UI.")
    print("="*60 + "\n")
 
 
# ── Main ──────────────────────────────────────────────────
if __name__ == "__main__":
    print("[*] Waiting for Wazuh Indexer to be ready...")
    for attempt in range(30):
        try:
            r = requests.get(
                f"{INDEXER_URL}/_cluster/health",
                auth=(INDEXER_USER, INDEXER_PASS),
                verify=False,
                timeout=5
            )
            if r.status_code == 200:
                print("[+] Wazuh Indexer is ready.")
                break
        except Exception:
            pass
        print(f"  Attempt {attempt+1}/30 — retrying in 10 seconds...")
        time.sleep(10)
    else:
        print("[!] Could not connect to Wazuh Indexer. Check docker-compose logs.")
        exit(1)
 
    events, meta = build_scenario_events()
    inject_events(events)
    print_summary(meta)
 
