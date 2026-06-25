import os, requests
from dotenv import load_dotenv
load_dotenv()

print("--- keys ---")
for k in ('URLSCAN_DAEMON','ALIENVAULT_DAEMON','VIRUSTOTAL_DAEMON','ABUSEIPDB_DAEMON'):
    v = os.getenv(k)
    print(f"{k}: {'loaded ('+str(len(v))+' chars)' if v else 'MISSING'}")

print("--- network, no key needed ---")
try:
    r = requests.get('https://rdap.org/domain/google.com',
                     headers={'Accept':'application/rdap+json'}, timeout=30)
    print("rdap.org ->", r.status_code)
except Exception as e:
    print("rdap.org FAILED ->", type(e).__name__, e)

print("--- one keyed API ---")
try:
    r = requests.get('https://api.abuseipdb.com/api/v2/check',
                     headers={'Key': os.getenv('ABUSEIPDB_DAEMON') or '', 'Accept':'application/json'},
                     params={'ipAddress':'8.8.8.8','maxAgeInDays':90}, timeout=30)
    print("abuseipdb ->", r.status_code, r.text[:160])
except Exception as e:
    print("abuseipdb FAILED ->", type(e).__name__, e)