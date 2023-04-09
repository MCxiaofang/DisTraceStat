from geoip2.errors import AddressNotFoundError
from geoip2.database import Reader
from ipaddress import ip_address
from enum import Enum
import os, sys, json, requests

DIRNAME = os.path.abspath(os.path.dirname(__file__))
PATH_CITY = os.path.join(DIRNAME, 'db', 'GeoLite2-City.mmdb')
PATH_ASN = os.path.join(DIRNAME, 'db', 'GeoLite2-ASN.mmdb')

try:
    reader_city = Reader(PATH_CITY)
    reader_asn = Reader(PATH_ASN)
except FileNotFoundError as e:
    sys.exit(1)


class Source(Enum):
    geoip_db = 1
    ip138_api = 2


conf = {
    'src': Source.geoip_db
}


def get_hostname(ipaddress, length=24):
    """ 10.11.12.13/32 => 10.11.12.0/24 """
    if length < 1 or length > 32:
        length = 24
    return ipaddress.rsplit('.', 1)[0] + '.0/' + str(length)


def is_valid(ip: str) -> bool:
    """Check whether the IP address is valid"""
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False


def is_limited(ip: str) -> bool:
    """ if is limited by private configuration """
    if ip[0:3] == '11.':
        return True
    return False


def is_private(ip: str) -> bool:
    """Check whether the IP address is private"""
    if not is_valid(ip):
        return False

    return ip_address(ip.strip()).is_private


def is_abroad(ip: str, default=False) -> bool:
    """Check whether the IP address is abroad"""
    res = getIPReader(ip, type='city')
    if res == None:
        return default

    Country_IsoCode = res.country.iso_code
    if Country_IsoCode == "CN":
        return False
    else:
        return True
    

def get_cnt_code(ip: str) -> str:
    """Get the country code of the IP address"""
    res = getIPReader(ip, type='city')
    if res == None:
        return 'None'

    Country_IsoCode = res.country.iso_code
    return Country_IsoCode


def get_addr(ip: str, src=None) -> str:
    if src == None:
        src = conf['src']

    if src == Source.geoip_db:
        try:
            res = reader_city.city(ip)
        except AddressNotFoundError:
            return 'AddressNotFoundError'

        Country_Name = res.country.name
        City_Name = res.city.name
        specName = res.subdivisions.most_specific.name

        if City_Name:
            return Country_Name + ' ' + City_Name
        elif specName:
            return Country_Name + ' ' + specName
        else:
            return Country_Name
    elif src == Source.ip138_api:
        url = "http://api.ip138.com/ip/?ip=" + ip + "&datatype=jsonp"
        headers = {'token': 'fc1fb5daf52167342161367d7b2f9bb2'}
        try:
            res = requests.get(url, headers=headers)
        except Exception as e:
            return f"Can't get {ip} address on ip138"

        if res.status_code == 200:
            info = json.loads(res.text)['data']
            addr = ''
            for i in range(4):
                addr = addr + info[i] + ' '
            return addr.strip()
        else:
            return f"Can't get {ip} address on ip138, status_code={res.status_code}"


def getIPReader(ip: str, type='city'):
    if type == 'city':
        try:
            return reader_city.city(ip)
        except AddressNotFoundError:
            return None
    elif type == 'asn':
        try:
            return reader_asn.asn(ip)
        except AddressNotFoundError:
            return None


def get_cnt_name(ip: str) -> str:
    res = getIPReader(ip, type='city')
    if res is None:
        return ''
    return res.country.name


def get_asn(ip: str):
    res = getIPReader(ip, type='asn')
    if res is None:
        return ''
    return res.autonomous_system_number


def get_asn_name(ip: str):
    res = getIPReader(ip, type='asn')
    if res is None:
        return ''
    return res.autonomous_system_organization


if __name__ == "__main__":
    IP = input("ipmsg test ip:")
    response = getIPReader(IP)
    if response is not None:
        Country_IsoCode = response.country.iso_code
        Country_Name = response.country.name
        Country_NameCN = response.country.names['zh-CN']
        Sub_SpecName = response.subdivisions.most_specific.name
        Sub_SpecISP = response.subdivisions.most_specific.iso_code
        City_Name = response.city.name
        City_PostalCode = response.postal.code
        Location_Latitude = response.location.latitude
        Location_Longitude = response.location.longitude
        print('\n[*] Target: ' + IP + ' GeoLite2-Located ')
        print('Country_IsoCode        : ' + Country_IsoCode)
        print('Country_Name           : ' + Country_Name)
        print('Country_NameCN         : ' + Country_NameCN)
        if Sub_SpecName is not None:
            print('Sub_SpecName:          : ' + Sub_SpecName)
            print('Sub_SpecISP            : ' + Sub_SpecISP)
        if City_Name is not None:
            print('City_Name              : ' + City_Name)
        if City_PostalCode is not None:
            print('City_PostalCode        : ' + City_PostalCode)
        print('Location_Latitude      : ' + str(Location_Latitude))
        print('Location_Longitude     : ' + str(Location_Longitude))
        response = reader_asn.asn(IP)
        print('autonomous_system_number       : ' + str(response.autonomous_system_number))
        print('autonomous_system_organization : ' + response.autonomous_system_organization)

    url = "http://api.ip138.com/ip/?ip=" + IP + "&datatype=jsonp"
    headers = {'token': 'fc1fb5daf52167342161367d7b2f9bb2'}
    r = requests.get(url, headers=headers)
    print(json.loads(r.text)['data'])
