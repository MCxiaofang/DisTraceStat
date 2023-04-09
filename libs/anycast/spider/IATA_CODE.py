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

def get_info(letter):
    res = {}
    source_url = f"https://www.nationsonline.org/oneworld/IATA_Codes/airport_code_{letter}.htm"

    response = requests.get(source_url,headers=headers)

    response.encoding = 'uft-8'
    html = response.text
    soup = BeautifulSoup(html, 'html.parser')
    label_table = soup.find('table')
    labels_tr = label_table.find_all('tr')

    for label_tr in labels_tr:
        labels_td = label_tr.find_all('td')
        if len(labels_td) < 4:
            continue

        City      = labels_td[0].text.strip()
        Country   = labels_td[2].text.strip()
        IATA_code = labels_td[3].text.strip()

        if len(IATA_code) < 3:
            continue
        res[IATA_code] = {'City': City, 'Country': Country}

    return res

def download():
    res = {}

    for i in range(97,120):
        print(chr(i))
        res.update(get_info(chr(i)))
    res.update(get_info('xyz'))

    with open(dirs + '/IATA_CODE.json', 'w') as f:
        f.write(json.dumps(res, indent=4, separators=(',', ':')))


if __name__ == "__main__":
    download()

    
#print(json.dumps(res, indent=4, separators=(',', ':')))