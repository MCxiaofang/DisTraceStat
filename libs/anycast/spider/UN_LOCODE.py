import json
import requests
import os
from bs4 import BeautifulSoup

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) '
                        'AppleWebKit/537.36 (KHTML, like Gecko)'
                        'Chrome/81.0.4044.138 Safari/537.36'
                        ' MicroMessenger/7.0.9.501 NetType/WIFI'
                        ' MiniProgramEnv/Windows WindowsWechat',
}
dirs = os.path.abspath(os.path.dirname(__file__))

def get_cnt_info():
    res = {}
    source_url = "https://unece.org/trade/cefact/unlocode-code-list-country-and-territory"

    response = requests.get(source_url,headers=headers)

    response.encoding = 'uft-8'
    html = response.text
    soup = BeautifulSoup(html, 'html.parser')
    label_table = soup.find('table')
    labels_tr = label_table.find_all('tr')

    for label_tr in labels_tr:
        labels_td = label_tr.find_all('td')
        if len(labels_td) < 2:
            continue

        ISO_3166 = labels_td[0].text.strip()
        Country  = labels_td[1].find('a').text.strip()

        res[ISO_3166] = Country

    return res

def get_city_info(cnt_code, city_code):
    name = ''
    cnt_code  = cnt_code.lower()
    city_code = city_code.upper()

    source_url = f"https://service.unece.org/trade/locode/{cnt_code}.htm"

    response = requests.get(source_url,headers=headers)

    response.encoding = 'uft-8'
    html = response.text
    soup = BeautifulSoup(html, 'html.parser')
    label_table = soup.find_all('table')[2]
    labels_tr = label_table.find_all('tr')[1:]
    
    for label_tr in labels_tr:
        labels_td = label_tr.find_all('td')

        LOCODE = labels_td[1].text.strip().replace('\u00a0', '').replace(cnt_code.upper(), '')
        if len(LOCODE) < 3:
            continue
        
        if LOCODE != city_code:
            continue
        else:
            name = labels_td[2].text.strip()
            break
    
    return name


def get_city_infos(cnt_code):
    res = {}
    cnt_code  = cnt_code.lower()

    source_url = f"https://service.unece.org/trade/locode/{cnt_code}.htm"

    for i in range(5):
        try:
            response = requests.get(source_url,headers=headers,timeout=30)
        except Exception:
            if i == 4: return 'not response'
            pass
        else:
            break
        
    response.encoding = 'uft-8'
    html = response.text
    soup = BeautifulSoup(html, 'html.parser')
    label_table = soup.find_all('table')[2]
    labels_tr = label_table.find_all('tr')[1:]
    
    for label_tr in labels_tr:
        labels_td = label_tr.find_all('td')

        LOCODE = labels_td[1].text.strip().replace('\u00a0', '').replace(cnt_code.upper(), '')
        if len(LOCODE) < 3:
            continue
        
        res[LOCODE] = labels_td[2].text.strip()
    
    return res


def download_cnt():
    cnt = get_cnt_info()

    with open(dirs + '/CNT_NAME.json', 'w') as f:
        f.write(json.dumps(cnt, indent=4, separators=(',', ':')))


def download_all():
    res = {}
    cnt = get_cnt_info()
    for code, name in cnt.items():
        print(code, name)
        info = get_city_infos(code)
        res[code] = {}
        res[code]['city'] = info
        res[code]['name'] = name
    
    with open(dirs + '/UN_LOCODE.json', 'w') as f:
        f.write(json.dumps(res, indent=4, separators=(',', ':')))

if __name__ == "__main__":
    download_cnt()