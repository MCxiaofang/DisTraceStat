from scapy.volatile import RandShort
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.sendrecv import sr1
from scapy.config import conf
from threading import Thread
import random
import string
import requests
import socket
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from datetime import timezone
from datetime import timedelta

conf.verb = 0
MAX_THREAD = 10
SHA_TZ = timezone(
    timedelta(hours=8),
    name='Asia/Shanghai',
)

target = {
    "root": {
        "198.97.190.53": "h.root-servers.net",
        "192.203.230.10": "e.root-servers.net",
        "192.112.36.4": "g.root-servers.net",
        "192.33.4.12": "c.root-servers.net",
        "198.41.0.4": "a.root-servers.net",
        "199.7.83.42": "l.root-servers.net",
        "192.36.148.17": "i.root-servers.net",
        "192.58.128.30": "j.root-servers.net",
        "193.0.14.129": "k.root-servers.net",
        "202.12.27.33": "m.root-servers.net",
        "192.5.5.241": "f.root-servers.net",
        "199.7.91.13": "d.root-servers.net",
        "199.9.14.201": "b.root-servers.net"
    },
    "recur":{
        "8.8.8.8": "8.8.8.8",
        "1.1.1.1": "1.1.1.1",
        "9.9.9.9": "9.9.9.9"
    }
}


class MutilThread(Thread):
    def __init__(self, func, *args):
        super(MutilThread, self).__init__()
        self.func = func
        self.args = args

    def run(self):
        self.result = self.func(*self.args)

    def get_result(self):
        return self.result


class DNSRoute:
    def __init__(self, dst, src='127.0.0.1', redo=3, timeout=2, minttl=1, maxttl=30):
        self.dst = dst
        self.src = src
        self.redo = redo
        self.minttl = minttl
        self.maxttl = maxttl
        self.timeout = timeout
        self.route = None

    def get_route_info(self):
        if self.route is None:
            self.batch_trace()

        return self.route

    def batch_trace(self):
        route = []
        redo = self.redo

        if redo == 1:
            res = self.single_trace()
            route.append(res)
            self.route = route
            return

        while (redo):
            thread_list = []
            for _ in range(min(redo, MAX_THREAD)):
                t = MutilThread(self.single_trace)
                t.setDaemon(True)
                t.start()
                thread_list.append(t)

            for t in thread_list:
                t.join()

            for t in thread_list:
                trace_res = t.get_result()
                trace_res[0] = self.src
                route.append(trace_res)

            redo = redo - min(redo, MAX_THREAD)

        self.route = route

    def single_trace(self):
        res = {}

        IP_id = RandShort()
        sport = RandShort()
        dport = 53

        for ttl in range(self.minttl, self.maxttl + 1):
            l3 = IP(dst=self.dst, id=IP_id, ttl=ttl) / \
                UDP(sport=sport, dport=dport)
            l4 = DNS(id=RandShort(), qd=DNSQR(qname=rand_domain()))

            ans = sr1(l3 / l4, timeout=self.timeout)

            if ans is None:
                res[ttl] = None
            else:
                res[ttl] = ans[IP].src

            if res[ttl] == self.dst:
                break

        return res


def rand_domain(length=6, level=1, top='com'):
    """ generate a random domain, which top level name's length is length"""
    domain = ''
    for _ in range(level):
        random_str = ''.join(random.choice(
            string.ascii_lowercase + string.digits) for _ in range(length))
        domain = domain + random_str + '.'
    return domain + top


def get_one_id(info):
    timeout = 2
    qname = 'hostname.bind'

    ip, name = info

    for i in range(5):
        l3 = IP(dst=ip, id=RandShort()) / UDP(sport=RandShort(), dport=53)
        l4 = DNS(ad=1, id=RandShort(), qd=DNSQR(
            qname=qname, qtype=16, qclass=3))

        ans = sr1(l3 / l4, timeout=timeout)

        if ans != None and ans.getlayer(DNS).ancount > 0:
            an = ans.getlayer(DNS).an
            for dnsrr in an.iterpayloads():
                if dnsrr.type == 16 and dnsrr.rclass == 3:
                    return name, dnsrr.rdata[0].decode('ascii')
        print(f'retry {i + 1} for {name}')
    return None


def get_identifiers():
    chaos = {}

    executor = ThreadPoolExecutor(max_workers=13)
    all_tasks = [executor.submit(get_one_id, (info))
                 for info in target["root"].items()]

    for future in as_completed(all_tasks):
        res = future.result()
        if res != None:
            chaos[res[0]] = res[1]

    chaos_sorted = {}
    for i in sorted(chaos):
        chaos_sorted[i] = chaos[i]

    return chaos_sorted


def traceroute(dst, redo):
    route = DNSRoute(dst=dst, redo=redo)
    route.batch_trace()
    return dst, route.get_route_info()

if __name__ == "__main__":
    # paths
    paths = {}
    ips = list(target["root"].keys()) + list(target["recur"].keys())
    thread_list = []
    for ip in ips:
        t = MutilThread(traceroute, ip, 10)
        t.setDaemon(True)
        t.start()
        thread_list.append(t)
    for t in thread_list:
        t.join()
    for t in thread_list:
        ip, path = t.get_result()
        paths[ip] = path

    # chaos
    chaos = get_identifiers()

    # infos
    utc_now = datetime.utcnow().replace(tzinfo=timezone.utc)
    beijing_now = utc_now.astimezone(SHA_TZ)

    # conbine res
    res = {
        "paths": paths,
        "infos": {
            "city": socket.gethostname(),
            "time": beijing_now.strftime("%Y_%m_%d_%H_%M_%S")
        },
        "chaos": chaos
    }

    # print(json.dumps(res, indent=4, separators=(',', ':')))

    requests.post("http://47.93.7.134:8000/examples/upload/recvdata", json=res)
