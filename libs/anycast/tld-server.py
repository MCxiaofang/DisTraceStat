import json, yaml, os, time, sys
from scapy.volatile import RandShort
from scapy.sendrecv import sr, sr1
from scapy.layers.inet import IP, UDP, traceroute, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
from scapy.config import conf
from concurrent.futures import ThreadPoolExecutor, as_completed

DIRNAME = os.path.abspath(os.path.dirname(__file__))
PATH_DB = os.path.join(DIRNAME, 'db')

conf.verb = 0

hot_tlds = ["com", "icu", "cn","net", "org", "ru"]

DB_TLD = 0

def id2address(chaos):
    pass

def get_id(info):
    timeout = 5
    qname = 'hostname.bind'

    name, ips = info

    for ip in ips.values():
        l3 = IP(dst=ip, id=RandShort()) / UDP(sport=RandShort(), dport=53)
        l4 = DNS(ad=1, id=RandShort(), qd=DNSQR(qname=qname, qtype=16, qclass=3))

        ans = sr1(l3 / l4, timeout=timeout)


        if ans != None and ans.getlayer(DNS).ancount > 0:
            an = ans.getlayer(DNS).an
            for dnsrr in an.iterpayloads():
                if dnsrr.type == 16 and dnsrr.rclass == 3:
                    return name, dnsrr.rdata[0].decode('ascii')
        print(f'retry for {name}, {ip} failed')
    return None

def get_ids_multhreads(tld_names):
    infos = {}
    for name in tld_names:
        infos[name] = DB_TLD[name]['record']

    executor = ThreadPoolExecutor(max_workers=20)
    all_tasks = [executor.submit(get_id, (info)) for info in infos.items()]

    chaos = {}
    for future in as_completed(all_tasks):
        res = future.result()
        if res != None:
            chaos[res[0]] = res[1]

    chaos_sorted = {}
    for i in sorted (chaos) : 
         chaos_sorted[i] = chaos[i]

    return chaos_sorted
        

def init():
    global DB_TLD
    with open(os.path.join(PATH_DB, 'tlds_domain.json'), 'r') as f:
        DB_TLD= json.loads(f.read())


init()

if __name__ == "__main__":
    res = get_ids_multhreads(hot_tlds)
    print(json.dumps(res, indent=4, separators=(',', ':')))