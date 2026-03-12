import json
import re
import csv
import sys
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── User Inputs ──────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("  NGFW POLICY MANAGER - Configuration")
print("=" * 70)

VMANAGE_HOST    = input("Enter vManage Host (e.g. 192.168.1.1 or vmanage.example.com): ").strip()
BASE_URL        = f"https://{VMANAGE_HOST}"
USERNAME        = input("Enter Username: ").strip()
PASSWORD        = input("Enter Password: ").strip()

print()
NEW_POLICY_NAME = input("Enter New Policy Name: ").strip()
NEW_POLICY_DESC = input("Enter New Policy Description: ").strip()
CSV_FILE        = input("Enter CSV File Path: ").strip()

# ─── Static Configuration ────────────────────────────────────────────────────
SKIP_PORT_OBJECTS = False

# ─── Mode Selection ──────────────────────────────────────────────────────────
# "create" = Create new profile + parcels + policy from CSV
# "update" = Add new parcels from CSV to existing profile, update policy
MODE = "create"

# For UPDATE mode - set these (printed at end of CREATE mode)
EXISTING_PROFILE_ID = "002d9fe3-2e0f-4235-8bd9-d074d02a9633"
EXISTING_POLICY_ID  = "2ce5f07b-6870-41ba-b09f-e0e6a734c6d5"

# ─── API Settings ────────────────────────────────────────────────────────────
API_TIMEOUT = 120
API_DELAY   = 1
MAX_RETRIES = 3
RETRY_DELAY = 5

# ─── Helpers ─────────────────────────────────────────────────────────────────

def api_post(session, url, payload, description="API call"):
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            print(f"  [{description}] Attempt {attempt}/{MAX_RETRIES}...")
            resp = session.post(url, json=payload, timeout=API_TIMEOUT)
            if resp.status_code in (200, 201):
                return resp
            elif resp.status_code == 429:
                wait = RETRY_DELAY * attempt
                print(f"  [{description}] ⚠️ Rate limited. Waiting {wait}s...")
                time.sleep(wait)
                continue
            else:
                print(f"  [{description}] ❌ HTTP {resp.status_code}")
                print(f"  [{description}] Response: {resp.text[:500]}")
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY)
                    continue
                return resp
        except requests.exceptions.Timeout:
            print(f"  [{description}] ⚠️ Timeout after {API_TIMEOUT}s")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
                continue
            return None
        except requests.exceptions.ConnectionError as e:
            print(f"  [{description}] ⚠️ Connection error: {e}")
            if attempt < MAX_RETRIES:
                try:
                    re_auth(session)
                except:
                    pass
                time.sleep(RETRY_DELAY)
                continue
            return None
        except Exception as e:
            print(f"  [{description}] ❌ Unexpected error: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
                continue
            return None
    return None

def api_put(session, url, payload, description="API PUT"):
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            print(f"  [{description}] Attempt {attempt}/{MAX_RETRIES}...")
            resp = session.put(url, json=payload, timeout=API_TIMEOUT)
            if resp.status_code in (200, 201):
                return resp
            elif resp.status_code == 429:
                wait = RETRY_DELAY * attempt
                print(f"  [{description}] ⚠️ Rate limited. Waiting {wait}s...")
                time.sleep(wait)
                continue
            else:
                print(f"  [{description}] ❌ HTTP {resp.status_code}")
                print(f"  [{description}] Response: {resp.text[:500]}")
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY)
                    continue
                return resp
        except requests.exceptions.Timeout:
            print(f"  [{description}] ⚠️ Timeout")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
                continue
            return None
        except requests.exceptions.ConnectionError as e:
            print(f"  [{description}] ⚠️ Connection error: {e}")
            if attempt < MAX_RETRIES:
                try:
                    re_auth(session)
                except:
                    pass
                time.sleep(RETRY_DELAY)
                continue
            return None
        except Exception as e:
            print(f"  [{description}] ❌ Error: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
                continue
            return None
    return None

def api_get(session, url, description="API GET"):
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = session.get(url, timeout=API_TIMEOUT)
            if resp.status_code == 200:
                return resp
            else:
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY)
                    continue
                return resp
        except Exception as e:
            print(f"  [{description}] ❌ Error: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
                continue
            return None
    return None

def re_auth(session):
    session.post(
        f"{BASE_URL}/j_security_check",
        data={"j_username": USERNAME, "j_password": PASSWORD},
        timeout=30
    )
    resp = session.get(f"{BASE_URL}/dataservice/client/token", timeout=30)
    if resp.status_code == 200:
        token = resp.text.strip()
        session.headers.update({"X-XSRF-TOKEN": token})
        print("  [RE-AUTH] ✅ Re-authenticated")

def validate_cidr(cidr: str) -> bool:
    try:
        import ipaddress
        ipaddress.ip_network(cidr, strict=False)
        return True
    except (ValueError, AttributeError):
        return False

def ensure_cidr(ip_str: str) -> str:
    ip_str = ip_str.strip()
    if "/" not in ip_str:
        ip_str = ip_str + "/32"
    return ip_str

def is_empty_or_dash(value: str) -> bool:
    return not value or value.strip() == "" or value.strip() == "-"

def sanitize_ip_list(raw: str) -> list:
    if is_empty_or_dash(raw):
        return []
    normalized = raw.replace(";", ",")
    parts = [p.strip() for p in normalized.split(",") if p.strip()]
    clean = []
    for p in parts:
        cidr = ensure_cidr(p)
        if validate_cidr(cidr):
            clean.append(cidr)
    return clean

def sanitize_port_value(raw: str) -> list:
    if is_empty_or_dash(raw):
        return []
    normalized = raw.replace(";", ",")
    parts = [p.strip() for p in normalized.split(",") if p.strip()]
    clean = []
    for p in parts:
        if re.match(r'^\d+(-\d+)?$', p):
            if '-' in p:
                start, end = p.split('-')
                if 1 <= int(start) <= 65535 and 1 <= int(end) <= 65535:
                    clean.append(p)
            else:
                if 1 <= int(p) <= 65535:
                    clean.append(p)
    return clean

def process_ip_field(field_type, field_data, cache, field_name):
    if is_empty_or_dash(field_data):
        return None
    if field_type == "object":
        object_names = [n.strip() for n in re.split(r'[;,]', field_data) if n.strip()]
        uuid_list = []
        for obj_name in object_names:
            uuid = cache.resolve("security-data-ip-prefix", obj_name)
            if not uuid:
                return None
            uuid_list.append(uuid)
        if field_name == "source":
            return {"sourceDataPrefixList": {"refId": {"optionType": "global", "value": uuid_list}}}
        else:
            return {"destinationDataPrefixList": {"refId": {"optionType": "global", "value": uuid_list}}}
    elif field_type == "value":
        ip_list = sanitize_ip_list(field_data)
        if not ip_list:
            return None
        if field_name == "source":
            return {"sourceIp": {"ipv4Value": {"optionType": "global", "value": ip_list}}}
        else:
            return {"destinationIp": {"ipv4Value": {"optionType": "global", "value": ip_list}}}
    return None

def process_port_field(port_type, port_data, cache, field_name):
    if is_empty_or_dash(port_data):
        return None
    if port_type == "object":
        if SKIP_PORT_OBJECTS:
            return None
        # Port objects can be comma/semicolon separated
        port_names = [n.strip() for n in re.split(r'[;,]', port_data) if n.strip()]
        uuid_list = []
        for pname in port_names:
            uuid = cache.resolve("security-port", pname)
            if not uuid:
                print(f"  ⚠️ Port object not found: '{pname}'")
                return None
            uuid_list.append(uuid)
        
        # Match working format: value (array) BEFORE optionType
        if field_name == "source":
            return {
                "sourcePortList": {
                    "refId": {
                        "value": uuid_list,
                        "optionType": "global"
                    }
                }
            }
        else:
            return {
                "destinationPortList": {
                    "refId": {
                        "value": uuid_list,
                        "optionType": "global"
                    }
                }
            }
    elif port_type == "value":
        ports = sanitize_port_value(port_data)
        if not ports:
            return None
        if field_name == "source":
            return {"sourcePort": {"portValue": {"optionType": "global", "value": ports}}}
        else:
            return {"destinationPort": {"portValue": {"optionType": "global", "value": ports}}}
    return None

def process_protocol_field(proto_type, proto_data, cache):
    if is_empty_or_dash(proto_data):
        return None
    if proto_type == "object":
        proto_names = [n.strip() for n in re.split(r'[;,]', proto_data) if n.strip()]
        uuid_list = []
        for pname in proto_names:
            uuid = cache.resolve("security-protocolname", pname)
            if not uuid:
                return None
            uuid_list.append(uuid)
        return {"protocolNameList": {"refId": {"optionType": "global", "value": uuid_list}}}
    elif proto_type in ("value", "name"):
        proto_names = [p.strip().lower() for p in re.split(r'[;,]', proto_data) if p.strip()]
        if proto_names:
            return {"protocolName": {"optionType": "global", "value": proto_names}}
    return None

# ─── Authentication ───────────────────────────────────────────────────────────

def authenticate():
    print("=" * 70)
    print("[AUTH] Authenticating...")
    session = requests.Session()
    session.verify = False
    resp = session.post(
        f"{BASE_URL}/j_security_check",
        data={"j_username": USERNAME, "j_password": PASSWORD},
        timeout=30
    )
    if resp.status_code not in (200, 302, 303):
        print(f"[AUTH] ❌ Failed: {resp.status_code}")
        sys.exit(1)
    resp = session.get(f"{BASE_URL}/dataservice/client/token", timeout=30)
    if resp.status_code != 200:
        print(f"[AUTH] ❌ Token failed: {resp.status_code}")
        sys.exit(1)
    token = resp.text.strip()
    session.headers.update({
        "X-XSRF-TOKEN": token,
        "Content-Type": "application/json",
        "Accept": "application/json"
    })
    print("[AUTH] ✅ Success")
    print("=" * 70)
    return session

# ─── Policy Object Profile ID Retrieval ───────────────────────────────────────

def get_policy_object_feature_profile_id(session):
    """
    Finds the EXISTING global Feature Profile of type 'policy-object'
    using the authenticated session.
    """
    api_endpoint = "/dataservice/v1/feature-profile/sdwan/policy-object"
    url = BASE_URL + api_endpoint

    print("\n[INIT] Searching for existing Policy Object Feature Profile...")

    try:
        response = session.get(url=url, timeout=API_TIMEOUT, verify=False)

        if response.status_code == 200:
            data = response.json()

            profiles = []
            if isinstance(data, dict):
                profiles = data.get('data', [])
            elif isinstance(data, list):
                profiles = data

            if len(profiles) > 0:
                existing_profile = profiles[0]
                p_id   = existing_profile.get('profileId')
                p_name = existing_profile.get('profileName')
                print(f"[INIT] ✅ Found existing profile '{p_name}'. ID: {p_id}")
                return p_id
            else:
                print("[INIT] ❌ No policy-object profiles found.")
                return None
        else:
            print(f"[INIT] ❌ API call failed. Status: {response.status_code}")
            print(f"       Response: {response.text[:500]}")
            return None

    except Exception as e:
        print(f"[INIT] ❌ Exception during profile search: {e}")
        return None

# ─── Object Cache ─────────────────────────────────────────────────────────────

class ObjectCache:
    LIST_TYPES = [
        "security-data-ip-prefix",
        "security-port",
        "security-zone",
        "security-protocolname"
    ]

    def __init__(self, session, policy_object_id):
        self.session          = session
        self.policy_object_id = policy_object_id
        self.cache            = {}
        self._load_all()

    def _load_all(self):
        print("\n[CACHE] Loading...")
        for list_type in self.LIST_TYPES:
            url = (
                f"{BASE_URL}/dataservice/v1/feature-profile/sdwan/policy-object"
                f"/{self.policy_object_id}/{list_type}"
            )
            try:
                resp = self.session.get(url, timeout=API_TIMEOUT)
                if resp.status_code != 200:
                    continue
                items = resp.json()
                if isinstance(items, dict):
                    items = items.get("data", [])
                count = 0
                for item in items:
                    pid  = item.get("parcelId")
                    name = item.get("name") or item.get("payload", {}).get("name")
                    if name and pid:
                        self.cache[(list_type, name.lower())] = pid
                        count += 1
                print(f"[CACHE] {list_type}: {count}")
            except Exception as e:
                print(f"[CACHE] ❌ Error loading {list_type}: {e}")
        print(f"[CACHE] ✅ {len(self.cache)} total objects loaded")

    def resolve(self, list_type, name):
        return self.cache.get((list_type, name.strip().lower()))

# ─── CSV Parsing ──────────────────────────────────────────────────────────────

def parse_csv_by_zone_pairs(filepath, cache):
    print("\n[CSV] Parsing...")
    zone_pair_rules  = {}
    any_any_converted = 0
    skipped_rows      = 0

    try:
        with open(filepath, "r", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            next(reader)
            for idx, row in enumerate(reader, 1):
                if len(row) < 13:
                    continue
                src_zone = row[0].strip()
                dst_zone = row[1].strip()
                action   = row[12].strip().lower()
                if action not in ("inspect", "pass", "drop"):
                    continue
                if is_empty_or_dash(src_zone) or is_empty_or_dash(dst_zone):
                    continue

                entries = []
                failed  = False

                if not is_empty_or_dash(row[3]):
                    e = process_ip_field(row[2].strip().lower(), row[3], cache, "source")
                    if e:
                        entries.append(e)
                    else:
                        failed = True

                if not is_empty_or_dash(row[5]) and not failed:
                    if not (row[4].strip().lower() == "object" and SKIP_PORT_OBJECTS):
                        e = process_port_field(row[4].strip().lower(), row[5], cache, "source")
                        if e:
                            entries.append(e)

                if not is_empty_or_dash(row[7]) and not failed:
                    e = process_ip_field(row[6].strip().lower(), row[7], cache, "destination")
                    if e:
                        entries.append(e)
                    else:
                        failed = True

                if not is_empty_or_dash(row[9]) and not failed:
                    if not (row[8].strip().lower() == "object" and SKIP_PORT_OBJECTS):
                        e = process_port_field(row[8].strip().lower(), row[9], cache, "destination")
                        if e:
                            entries.append(e)

                if not is_empty_or_dash(row[11]) and not failed:
                    e = process_protocol_field(row[10].strip().lower(), row[11], cache)
                    if e:
                        entries.append(e)
                    else:
                        failed = True

                if failed:
                    skipped_rows += 1
                    continue

                if not entries:
                    any_any_converted += 1
                    entries = []

                zone_pair = (src_zone, dst_zone)
                if zone_pair not in zone_pair_rules:
                    zone_pair_rules[zone_pair] = []

                rule_number = len(zone_pair_rules[zone_pair]) + 1
                seq = {
                    "actions": [],
                    "baseAction": {"optionType": "global", "value": action},
                    "disableSequence": {"optionType": "global", "value": False},
                    "match": {"entries": entries},
                    "sequenceId": {"optionType": "global", "value": str(rule_number)},
                    "sequenceName": {"optionType": "global", "value": f"Rule{rule_number}"},
                    "sequenceType": {"optionType": "global", "value": "ngfirewall"}
                }
                zone_pair_rules[zone_pair].append(seq)

    except Exception as e:
        print(f"[CSV] ❌ Error: {e}")
        sys.exit(1)

    total_rules = sum(len(r) for r in zone_pair_rules.values())
    print(f"[CSV] ✅ {len(zone_pair_rules)} zone pairs, {total_rules} total rules")
    if any_any_converted > 0:
        print(f"[CSV] ℹ️ {any_any_converted} any/any rules (empty entries)")
    if skipped_rows > 0:
        print(f"[CSV] ⚠️ {skipped_rows} rows skipped (unresolved objects)")

    for zp, rules in zone_pair_rules.items():
        print(f"  {zp[0]} -> {zp[1]}: {len(rules)} rules")

    return zone_pair_rules

# ─── vManage Operations ───────────────────────────────────────────────────────

def create_new_security_profile(session):
    print("\n[CREATE PROFILE] Creating...")
    payload = {"name": NEW_POLICY_NAME, "description": NEW_POLICY_DESC}
    url     = f"{BASE_URL}/dataservice/v1/feature-profile/sdwan/embedded-security"
    resp    = api_post(session, url, payload, "CREATE PROFILE")
    if resp and resp.status_code in (200, 201):
        result     = resp.json()
        profile_id = result.get("profileId") or result.get("id")
        print(f"[CREATE PROFILE] ✅ {profile_id}")
        return profile_id
    print("[CREATE PROFILE] ❌ Failed")
    return None

def get_existing_ngfw_parcels(session, security_profile_id):
    """Fetch existing NGFW parcels: name -> parcelId."""
    print(f"\n[EXISTING NGFW] Fetching existing parcels...")
    url      = f"{BASE_URL}/dataservice/v1/feature-profile/sdwan/embedded-security/{security_profile_id}/unified/ngfirewall"
    resp     = api_get(session, url, "GET EXISTING NGFW")
    existing = {}
    if resp and resp.status_code == 200:
        data    = resp.json()
        parcels = data.get("data", []) if isinstance(data, dict) else data
        if isinstance(parcels, list):
            for p in parcels:
                pid  = p.get("parcelId")
                name = p.get("payload", {}).get("name", "")
                if name and pid:
                    existing[name] = pid
        print(f"[EXISTING NGFW] ✅ Found {len(existing)} existing parcels")
        for name, pid in existing.items():
            print(f"  ♻️ {name} -> {pid}")
    return existing

def get_existing_policy(session, security_profile_id):
    """Fetch existing policy assembly."""
    print(f"\n[EXISTING POLICY] Fetching existing policy...")
    url  = f"{BASE_URL}/dataservice/v1/feature-profile/sdwan/embedded-security/{security_profile_id}/policy"
    resp = api_get(session, url, "GET EXISTING POLICY")
    if resp and resp.status_code == 200:
        data  = resp.json()
        items = data.get("data", []) if isinstance(data, dict) else data
        if isinstance(items, list) and len(items) > 0:
            policy    = items[0]
            policy_id = policy.get("parcelId")
            assembly  = policy.get("payload", {}).get("data", {}).get("assembly", [])
            print(f"[EXISTING POLICY] ✅ Policy ID: {policy_id}")
            print(f"[EXISTING POLICY] ✅ Existing assembly entries: {len(assembly)}")
            return policy_id, assembly
    print(f"[EXISTING POLICY] ⚠️ No existing policy found")
    return None, []

def create_ngfw_parcel(session, security_profile_id, zone_pair, sequences, index, total):
    src_zone, dst_zone = zone_pair
    parcel_name = f"NGFW_{src_zone}_to_{dst_zone}"
    print(f"\n[CREATE NGFW {index}/{total}] {parcel_name} ({len(sequences)} rules)")

    payload = {
        "name": parcel_name,
        "description": f"Rules: {src_zone} to {dst_zone}",
        "optimized": False,
        "containsUtd": False,
        "containsTls": False,
        "data": {
            "defaultActionType": {"optionType": "global", "value": "drop"},
            "sequences": sequences
        }
    }

    url  = f"{BASE_URL}/dataservice/v1/feature-profile/sdwan/embedded-security/{security_profile_id}/unified/ngfirewall"
    resp = api_post(session, url, payload, f"NGFW {index}/{total}")

    if resp and resp.status_code in (200, 201):
        result    = resp.json()
        parcel_id = result.get("parcelId")
        print(f"[CREATE NGFW {index}/{total}] ✅ {parcel_id}")
        return parcel_id
    else:
        print(f"[CREATE NGFW {index}/{total}] ❌ Failed")
        if resp:
            print(f"  Response: {resp.text[:500]}")
        return None

def build_assembly_entry(src_zone_name, dst_zone_name, ngfw_id, cache):
    """Build a single assembly entry."""
    src_zone_uuid = cache.resolve("security-zone", src_zone_name)
    if not src_zone_uuid:
        print(f"  ⚠️ Zone '{src_zone_name}' not found")
        return None

    if dst_zone_name.lower() == "self":
        dst_zone_value = {"optionType": "global", "value": "self"}
    else:
        dst_zone_uuid = cache.resolve("security-zone", dst_zone_name)
        if not dst_zone_uuid:
            print(f"  ⚠️ Zone '{dst_zone_name}' not found")
            return None
        dst_zone_value = {"refId": {"optionType": "global", "value": dst_zone_uuid}}

    return {
        "ngfirewall": {
            "refId": {"optionType": "global", "value": ngfw_id},
            "entries": [{
                "srcZone": {"refId": {"optionType": "global", "value": src_zone_uuid}},
                "dstZone": dst_zone_value
            }]
        }
    }

def create_policy(session, security_profile_id, assembly):
    """Create a NEW policy."""
    payload = {
        "name": NEW_POLICY_NAME + "_Policy",
        "description": "Security policy",
        "data": {
            "settings": {
                "securityLogging": {"optionType": "network-settings", "value": True}
            },
            "assembly": assembly
        }
    }

    with open("debug_policy_payload.json", "w") as f:
        json.dump(payload, f, indent=2)
    print(f"[CREATE POLICY] 💾 Saved to: debug_policy_payload.json")
    print(f"[CREATE POLICY] Assembly entries: {len(assembly)}")

    url  = f"{BASE_URL}/dataservice/v1/feature-profile/sdwan/embedded-security/{security_profile_id}/policy"
    resp = api_post(session, url, payload, "CREATE POLICY")

    if resp and resp.status_code in (200, 201):
        result    = resp.json()
        policy_id = result.get("parcelId") or result.get("id")
        print(f"[CREATE POLICY] ✅ Policy ID: {policy_id}")
        return policy_id
    else:
        print(f"[CREATE POLICY] ❌ Failed")
        if resp:
            print(f"  Response: {resp.text[:1000]}")
        return None

def update_policy(session, security_profile_id, policy_id, assembly):
    """Update an EXISTING policy."""
    payload = {
        "name": NEW_POLICY_NAME + "_Policy",
        "description": "Security policy",
        "data": {
            "settings": {
                "securityLogging": {"optionType": "network-settings", "value": True}
            },
            "assembly": assembly
        }
    }

    with open("debug_policy_update.json", "w") as f:
        json.dump(payload, f, indent=2)
    print(f"[UPDATE POLICY] 💾 Saved to: debug_policy_update.json")
    print(f"[UPDATE POLICY] Assembly entries: {len(assembly)}")

    url  = f"{BASE_URL}/dataservice/v1/feature-profile/sdwan/embedded-security/{security_profile_id}/policy/{policy_id}"
    resp = api_put(session, url, payload, "UPDATE POLICY")

    if resp and resp.status_code in (200, 201):
        print(f"[UPDATE POLICY] ✅ Success")
        return True
    else:
        print(f"[UPDATE POLICY] ❌ Failed")
        if resp:
            print(f"  Response: {resp.text[:1000]}")
        return False

# ─── CREATE Mode ──────────────────────────────────────────────────────────────

def run_create(session, cache, zone_pair_rules):
    """Create new profile + parcels + policy from scratch."""
    start_time = time.time()

    print(f"\n{'='*70}")
    print(f"[CREATE MODE] Creating everything from scratch")
    print(f"{'='*70}")

    # Step 1: Create profile
    security_profile_id = create_new_security_profile(session)
    if not security_profile_id:
        sys.exit(1)

    # Step 2: Create NGFW parcels
    total_pairs     = len(zone_pair_rules)
    ngfw_parcels    = []
    failed_parcels  = []

    for idx, (zone_pair, sequences) in enumerate(zone_pair_rules.items(), 1):
        ngfw_id = create_ngfw_parcel(session, security_profile_id, zone_pair, sequences, idx, total_pairs)
        if ngfw_id:
            ngfw_parcels.append((zone_pair, ngfw_id))
        else:
            failed_parcels.append(zone_pair)

        elapsed = time.time() - start_time
        pct     = (idx / total_pairs) * 100
        print(f"  📊 Progress: {idx}/{total_pairs} ({pct:.0f}%) | "
              f"✅ {len(ngfw_parcels)} | ❌ {len(failed_parcels)} | ⏱ {elapsed:.0f}s")
        if idx < total_pairs:
            time.sleep(API_DELAY)

    if not ngfw_parcels:
        print("[CREATE] ❌ No parcels created. Exiting.")
        sys.exit(1)

    # Step 3: Build assembly
    assembly = []
    for (src_zone, dst_zone), ngfw_id in ngfw_parcels:
        entry = build_assembly_entry(src_zone, dst_zone, ngfw_id, cache)
        if entry:
            assembly.append(entry)

    # Step 4: Create policy
    policy_id = create_policy(session, security_profile_id, assembly)

    elapsed = time.time() - start_time

    print(f"\n{'#'*70}")
    if policy_id:
        print(f"#  ✅ CREATE COMPLETE!")
    else:
        print(f"#  ⚠️ PARCELS CREATED BUT POLICY FAILED")
    print(f"#")
    print(f"#  Profile ID: {security_profile_id}")
    print(f"#  Policy ID:  {policy_id}")
    print(f"#  Parcels:    {len(ngfw_parcels)}/{total_pairs}")
    print(f"#  Time:       {elapsed:.0f}s ({elapsed/60:.1f}m)")
    print(f"#")
    print(f"#  ─── FOR FUTURE UPDATES ───────────────────────────")
    print(f"#  Set these in the script and change MODE to 'update':")
    print(f"#")
    print(f"#  MODE = \"update\"")
    print(f"#  EXISTING_PROFILE_ID = \"{security_profile_id}\"")
    print(f"#  EXISTING_POLICY_ID  = \"{policy_id}\"")
    print(f"#")
    print(f"#  Then update your CSV with new rules and run again.")
    print(f"{'#'*70}")

    if failed_parcels:
        print(f"\n  ❌ Failed parcels:")
        for fp in failed_parcels:
            print(f"    - {fp[0]} -> {fp[1]}")

# ─── UPDATE Mode ──────────────────────────────────────────────────────────────

def run_update(session, cache, zone_pair_rules):
    """Add new parcels from CSV to existing profile, update policy."""
    start_time = time.time()

    if not EXISTING_PROFILE_ID:
        print("[UPDATE] ❌ EXISTING_PROFILE_ID is not set!")
        print("[UPDATE] Run in CREATE mode first, then copy the IDs.")
        sys.exit(1)

    security_profile_id = EXISTING_PROFILE_ID

    print(f"\n{'='*70}")
    print(f"[UPDATE MODE] Adding new rules to existing profile")
    print(f"  Profile: {security_profile_id}")
    print(f"{'='*70}")

    # Step 1: Get existing NGFW parcels
    existing_ngfw = get_existing_ngfw_parcels(session, security_profile_id)

    # Step 2: Get existing policy and assembly
    policy_id, existing_assembly = get_existing_policy(session, security_profile_id)

    if not policy_id and EXISTING_POLICY_ID:
        policy_id = EXISTING_POLICY_ID
        print(f"[UPDATE] Using provided policy ID: {policy_id}")

    if not policy_id:
        print("[UPDATE] ❌ No existing policy found and EXISTING_POLICY_ID not set!")
        sys.exit(1)

    # Step 3: Create only NEW NGFW parcels (skip existing ones)
    total_pairs    = len(zone_pair_rules)
    new_parcels    = []
    reused_parcels = []
    failed_parcels = []

    print(f"\n[UPDATE] Processing {total_pairs} zone pairs from CSV...")

    for idx, (zone_pair, sequences) in enumerate(zone_pair_rules.items(), 1):
        src_zone, dst_zone = zone_pair
        parcel_name        = f"NGFW_{src_zone}_to_{dst_zone}"

        if parcel_name in existing_ngfw:
            existing_id = existing_ngfw[parcel_name]
            print(f"\n[NGFW {idx}/{total_pairs}] ♻️ EXISTS: {parcel_name} -> {existing_id}")
            reused_parcels.append((zone_pair, existing_id))
        else:
            ngfw_id = create_ngfw_parcel(session, security_profile_id, zone_pair, sequences, idx, total_pairs)
            if ngfw_id:
                new_parcels.append((zone_pair, ngfw_id))
            else:
                failed_parcels.append(zone_pair)
            time.sleep(API_DELAY)

        elapsed = time.time() - start_time
        pct     = (idx / total_pairs) * 100
        print(f"  📊 Progress: {idx}/{total_pairs} ({pct:.0f}%) | "
              f"♻️ {len(reused_parcels)} reused | ✅ {len(new_parcels)} new | "
              f"❌ {len(failed_parcels)} failed | ⏱ {elapsed:.0f}s")

    print(f"\n[UPDATE] Parcel Summary:")
    print(f"  ♻️ Reused:  {len(reused_parcels)}")
    print(f"  ✅ Created: {len(new_parcels)}")
    print(f"  ❌ Failed:  {len(failed_parcels)}")

    # Step 4: Build FULL assembly (existing + new)
    all_parcels = reused_parcels + new_parcels

    if not all_parcels:
        print("[UPDATE] ❌ No parcels available. Exiting.")
        sys.exit(1)

    print(f"\n[UPDATE] Building full assembly ({len(all_parcels)} zone pairs)...")

    full_assembly = []
    for (src_zone, dst_zone), ngfw_id in all_parcels:
        entry = build_assembly_entry(src_zone, dst_zone, ngfw_id, cache)
        if entry:
            full_assembly.append(entry)
            print(f"  ✅ {src_zone} -> {dst_zone}")

    if not full_assembly:
        print("[UPDATE] ❌ No valid assembly entries. Exiting.")
        sys.exit(1)

    # Step 5: Update the policy
    print(f"\n[UPDATE] Updating policy {policy_id} with {len(full_assembly)} entries...")
    success = update_policy(session, security_profile_id, policy_id, full_assembly)

    elapsed = time.time() - start_time

    print(f"\n{'#'*70}")
    if success:
        print(f"#  ✅ UPDATE COMPLETE!")
    else:
        print(f"#  ❌ UPDATE FAILED")
    print(f"#")
    print(f"#  Profile ID: {security_profile_id}")
    print(f"#  Policy ID:  {policy_id}")
    print(f"#  Reused:     {len(reused_parcels)} parcels")
    print(f"#  New:        {len(new_parcels)} parcels")
    print(f"#  Total:      {len(full_assembly)} assembly entries")
    print(f"#  Time:       {elapsed:.0f}s ({elapsed/60:.1f}m)")
    print(f"#")
    print(f"#  NEXT: Push the config group to the device in vManage")
    print(f"{'#'*70}")

    if failed_parcels:
        print(f"\n  ❌ Failed parcels:")
        for fp in failed_parcels:
            print(f"    - {fp[0]} -> {fp[1]}")

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "#" * 70)
    print("#  NGFW POLICY MANAGER")
    print(f"#  Mode: {MODE.upper()}")
    print(f"#  vManage: {VMANAGE_HOST}")
    print(f"#  CSV:  {CSV_FILE}")
    print("#" * 70)

    if MODE not in ("create", "update"):
        print(f"\n[ERROR] Invalid MODE: '{MODE}'")
        print(f"  Set MODE = \"create\" for new deployment")
        print(f"  Set MODE = \"update\" to add rules to existing profile")
        sys.exit(1)

    if MODE == "update" and not EXISTING_PROFILE_ID:
        print(f"\n[ERROR] UPDATE mode requires EXISTING_PROFILE_ID")
        print(f"  Run in CREATE mode first, then copy the IDs printed at the end.")
        sys.exit(1)

    # Authenticate first, then retrieve POLICY_OBJECT_PROFILE_ID dynamically
    session = authenticate()

    policy_object_profile_id = get_policy_object_feature_profile_id(session)
    if not policy_object_profile_id:
        print("\n[ERROR] ❌ Could not retrieve Policy Object Feature Profile ID.")
        print("         Verify the policy-object profile exists in vManage.")
        sys.exit(1)

    cache           = ObjectCache(session, policy_object_profile_id)
    zone_pair_rules = parse_csv_by_zone_pairs(CSV_FILE, cache)

    if not zone_pair_rules:
        print("[MAIN] No zone pairs found. Exiting.")
        sys.exit(0)

    total_rules = sum(len(r) for r in zone_pair_rules.values())

    print(f"\n{'='*70}")
    print(f"  PLAN: {MODE.upper()}")
    print(f"  Zone pairs: {len(zone_pair_rules)}")
    print(f"  Rules:      {total_rules}")
    if MODE == "update":
        print(f"  Profile:    {EXISTING_PROFILE_ID}")
        print(f"  Policy:     {EXISTING_POLICY_ID}")
    print(f"{'='*70}")

    confirm = input("\nProceed? [y/N]: ").strip().lower()
    if confirm != 'y':
        print("Cancelled.")
        sys.exit(0)

    if MODE == "create":
        run_create(session, cache, zone_pair_rules)
    else:
        run_update(session, cache, zone_pair_rules)

if __name__ == "__main__":
    main()