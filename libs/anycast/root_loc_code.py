import json, yaml, os, time, sys
# python3.6 need "pip insall pyyaml"
from scapy.volatile import RandShort
from scapy.sendrecv import sr, sr1
from scapy.layers.inet import IP, UDP, traceroute, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
from scapy.config import conf
from concurrent.futures import ThreadPoolExecutor, as_completed


conf.verb = 0

DB = {
    "IATA_CODE": [],
    'UN_LOCODE': [],
    'L_YAML': [],
    'trans': {},
    'ROOT': {}
}
RDNS = '114.114.114.114'
DIRNAME = os.path.abspath(os.path.dirname(__file__))
PATH_DB = os.path.join(DIRNAME, 'db')

sys.path.append(DIRNAME)
from ..ipmsg import get_cnt_code, get_addr


def recog_A(identifier: str) -> str:
    # nnn1-sin5
    return recog_J(identifier)

def recog_std_A(identifier: str) -> str:
    # nnn1-sin5
    return recog_std_J(identifier)


def recog_B(identifier: str) -> str:
    # b3-sin
    return recog_J(identifier)


def recog_std_B(identifier: str) -> str:
    # b3-sin
    return recog_std_J(identifier)


def recog_C(identifier: str) -> str:
    # sin1a.c.root-servers.org
    return recog_F(identifier)


def recog_std_C(identifier: str) -> str:
    # sin1a.c.root-servers.org
    return recog_std_F(identifier)


def recog_D(identifier: str) -> str:
    timeout = 5

    l3 = IP(dst=RDNS, id=RandShort()) / UDP(sport=RandShort(), dport=53)
    l4 = DNS(id=RandShort(), qd=DNSQR(qname=identifier))

    ans = sr1(l3 / l4, timeout=timeout)

    if ans != None and ans.getlayer(DNS).ancount > 0:
        an = ans.getlayer(DNS).an
        for dnsrr in an.iterpayloads():
            if dnsrr.type == 1:
                ipv4 = dnsrr.rdata
                return get_addr(ipv4)
    return None


def recog_std_D(identifier: str) -> str:
    timeout = 5

    l3 = IP(dst=RDNS, id=RandShort()) / UDP(sport=RandShort(), dport=53)
    l4 = DNS(id=RandShort(), qd=DNSQR(qname=identifier))

    ans = sr1(l3 / l4, timeout=timeout)

    if ans != None and ans.getlayer(DNS).ancount > 0:
        an = ans.getlayer(DNS).an
        for dnsrr in an.iterpayloads():
            if dnsrr.type == 1:
                ipv4 = dnsrr.rdata
                return get_cnt_code(ipv4)
    return None


def recog_E(identifier: str) -> str:
    # c01.HKG.eroot
    code = identifier.split('.')[1].upper()
    return recog_IATA_CODE(code)


def recog_std_E(identifier: str) -> str:
    # c01.HKG.eroot
    code = identifier.split('.')[1].upper()
    return recog_IATA_CODE_std(code)


def recog_F(identifier: str) -> str:
    # pek2a.f.root-servers.org
    code = identifier[:3].upper()

    return recog_IATA_CODE(code)


def recog_std_F(identifier: str) -> str:
    # pek2a.f.root-servers.org
    code = identifier[:3].upper()

    return recog_IATA_CODE_std(code)


def recog_H(identifier):
    # 001.hkg.h.root-servers.org
    code = identifier.split('.')[1].upper()

    return recog_IATA_CODE(code)


def recog_std_H(identifier):
    # 001.hkg.h.root-servers.org
    code = identifier.split('.')[1].upper()

    return recog_IATA_CODE_std(code)


def recog_I(identifier):
    # s1.bei
    code = identifier.split('.')[1].upper()

    city = DB['NETNOD_ID'][code]['city']
    cnt = DB['UN_LOCODE'][DB['NETNOD_ID'][code]['cnt_code']]['name']
    if city == cnt:
        return city
    else:
        return cnt + ' ' + city


def recog_std_I(identifier):
    # s1.bei
    code = identifier.split('.')[1].upper()

    return DB['NETNOD_ID'][code]['cnt_code']


def recog_J(identifier: str) -> str:
    # rootns-elpek3
    # nnn1-oak3
    id = identifier.split('-')[1]
    if len(id) > 4:
        code = id[2:5].upper()
    else:
        code = id[:3].upper()

    return recog_IATA_CODE(code)


def recog_std_J(identifier: str) -> str:
    # rootns-elpek3
    # nnn1-oak3
    id = identifier.split('-')[1]
    if len(id) > 4:
        code = id[2:5].upper()
    else:
        code = id[:3].upper()

    return recog_IATA_CODE_std(code)


def recog_K(identifier):
    # ns1.cn-ggz.k.ripe.net
    id = identifier.split('.')
    code = id[1].split('-')

    Country = DB['UN_LOCODE'][code[0].upper()]['name']
    City = DB['UN_LOCODE'][code[0].upper()]['city'][code[1].upper()]

    if City == Country:
        return Country
    else:
        return f"{Country} {City}"


def recog_std_K(identifier):
    # ns1.cn-ggz.k.ripe.net
    id = identifier.split('.')
    code = id[1].split('-')

    return code[0].upper()


def recog_L(identifier):
    code = identifier.split('-')
    cnt = DB['UN_LOCODE'][code[0].upper()]['name']
    city = DB['L_YAML'][code[0] + '-' + code[1]]['town']

    if city == cnt:
        return city
    else:
        return f'{cnt} {city}'


def recog_std_L(identifier):
    code = identifier.split('-')

    return code[0].upper()


def recog_M(identifier):
    # M-CDG-1
    code = identifier.split('-')[1].upper()

    return recog_IATA_CODE(code)


def recog_std_M(identifier):
    # M-CDG-1
    code = identifier.split('-')[1].upper()

    return recog_IATA_CODE_std(code)


def recog_IATA_CODE(code):
    if code not in DB['IATA_CODE']:
        return f'not found {code}'

    info = DB['IATA_CODE'][code]
    if info['Country'] == info['City']:
        return info['Country']
    else:
        return f"{info['Country']} {info['City']}"


def recog_IATA_CODE_std(code):
    if code not in DB['IATA_CODE']:
        return None

    info = DB['IATA_CODE'][code]
    country = info['Country']
    std_code_list = DB['trans']['IATA']
    if country in std_code_list:
        return std_code_list[country]
    else:
        return "IATA:" + country


def recog_name(name, id):
    if name == 'A':
        return recog_A(id)
    elif name == 'B':
        return recog_B(id)
    elif name == 'C':
        return recog_C(id)
    elif name == 'D':
        return recog_D(id)
    elif name == 'E':
        return recog_E(id)
    elif name == 'F':
        return recog_F(id)
    elif name == 'H':
        return recog_H(id)
    elif name == 'I':
        return recog_I(id)
    elif name == 'J':
        return recog_J(id)
    elif name == 'K':
        return recog_K(id)
    elif name == 'L':
        return recog_L(id)
    elif name == 'M':
        return recog_M(id)
    else:
        return None


def recog_code(name, id):
    if name == 'A':
        return recog_std_A(id)
    elif name == 'B':
        return recog_std_B(id)
    elif name == 'C':
        return recog_std_C(id)
    elif name == 'D':
        return recog_std_D(id)
    elif name == 'E':
        return recog_std_E(id)
    elif name == 'F':
        return recog_std_F(id)
    elif name == 'H':
        return recog_std_H(id)
    elif name == 'I':
        return recog_std_I(id)
    elif name == 'J':
        return recog_std_J(id)
    elif name == 'K':
        return recog_std_K(id)
    elif name == 'L':
        return recog_std_L(id)
    elif name == 'M':
        return recog_std_M(id)
    else:
        return None


def init():
    global DB

    with open(os.path.join(PATH_DB, 'IATA_CODE.json'), 'r') as f:
        DB['IATA_CODE'] = json.loads(f.read())

    with open(os.path.join(PATH_DB, 'l-root.yml'), 'r') as f:
        res = {}
        sites = yaml.load(f.read(), Loader=yaml.FullLoader)['Sites']
        for site in sites:
            for id in site['Identifiers']:
                res[id.split('.')[1]] = {'Country': site['Country'], 'town': site['Town']}
        DB['L_YAML'] = res

    with open(os.path.join(PATH_DB, 'UN_LOCODE.json'), 'r') as f:
        DB['UN_LOCODE'] = json.loads(f.read())

    with open(os.path.join(PATH_DB, 'root.json'), 'r') as f:
        DB['ROOT'] = json.loads(f.read())

    with open(os.path.join(PATH_DB, 'NETNOD_ID.json'), 'r') as f:
        DB['NETNOD_ID'] = json.loads(f.read())

    with open(os.path.join(PATH_DB, 'transformer.json'), 'r') as f:
        DB['trans'] = json.loads(f.read())


init()
