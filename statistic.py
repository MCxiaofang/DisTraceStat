import os, csv, json, sys
import csv
import json
from libs.anycast.root_loc_code import recog_name, recog_code
from libs.ipmsg import get_cnt_code, get_addr, is_private, is_abroad, is_limited, is_valid, get_asn, get_asn_name, get_cnt_name


DIRNAME = os.path.abspath(os.path.dirname(__file__))

CITYS = ["beijing", "chengdu", "guangzhou", "hangzhou", "huhehaote", "nanjing", "qingdao", "shanghai", "xianggang"]
# CITYS = ["beijing"]
CITY_CNNAME = {
    "beijing": "北京",
    "chengdu": "成都",
    "guangzhou": "广州",
    "hangzhou": "杭州",
    "huhehaote": "呼和浩特",
    "nanjing": "南京",
    "qingdao": "青岛",
    "shanghai": "上海",
    "xianggang": "香港"
}
ROOTS = {
    "H": "198.97.190.53",
    "E": "192.203.230.10",
    "G": "192.112.36.4",
    "C": "192.33.4.12",
    "A": "198.41.0.4" ,
    "L": "199.7.83.42",
    "I": "192.36.148.17",
    "J": "192.58.128.30",
    "K": "193.0.14.129" ,
    "M": "202.12.27.33",
    "F": "192.5.5.241",
    "D": "199.7.91.13",
    "B": "199.9.14.201"
}
RECUR = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def get_ip_infos(paths):
    infos = dict()
    for path in paths:
        for ip in path.values():
            if ip is None or not is_valid(ip) or is_private(ip) or is_limited(ip):
                continue
            infos[ip] = {
                "addr": get_addr(ip),
                'city': get_cnt_name(ip),
                "asn": get_asn(ip),
                "asn_name": get_asn_name(ip),
                'is_abroad': is_abroad(ip)
            }

    return infos



def getLocation(filepath):
    print("Processing file: {}".format(filepath))

    # read data
    res = []
    with open(filepath, "r") as f:
        data = json.load(f)
    chaos = data["chaos"]
    infos = data["infos"]
    paths_all = data["paths"]
    
    # read root info
    unparsed = []
    for name, id in chaos.items():
        name = name[0].upper()
        loc_code = recog_code(name, id)
        loc_name = recog_name(name, id)
        if loc_code != None:
            res.append([
                name,               # dst ip
                loc_code,           # loc_code
                loc_name,           # loc_name
                False,              # using traceroute
                '',                 # ttl gap
                infos["time"],      # time
                None                # paths
            ])
        else:
            unparsed.append(name)
    # print(json.dumps(res, indent=4, separators=(',', ':')))
    # save all chaos loc and traceroute loc for root server
    unparsed = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M"]    

    # read recursive info
    for name in RECUR + unparsed:
        if len(name) == 1: ip = ROOTS[name]
        else: ip = name

        paths = paths_all[ip]
        addrs = set()
        for path in paths:
            dst_ttl = max([int(ttl) for ttl in list(path.keys())])
            for ttl in range(dst_ttl-1, -1, -1):
                if path[str(ttl)] == None: continue
                if is_private(path[str(ttl)]): continue
                code = get_cnt_code(path[str(ttl)])
                addr = get_addr(path[str(ttl)])
                if addr not in addrs:
                    addrs.add(addr)
                    res.append([
                        name,               # dst ip
                        code,               # loc_code
                        addr,               # loc_name
                        True,               # using traceroute
                        str(dst_ttl) + '->' + str(ttl), # ttl gap
                        infos["time"],      # time
                        paths_all[ip]       # paths
                    ])
                break
    return res


def main():
    headers = ["src", "dst_target", "dst_loc_code", "dst_loc_name", "using_traceroute", "dst_ttl->loc_ttl", "time"]
    rows = []
    for city in CITYS:
        print("Processing city: {}".format(city))
        files = os.listdir(os.path.join(DIRNAME, city))
        for file in files:
            res = getLocation(os.path.join(DIRNAME, city, file))
            for record in res:
                row = [CITY_CNNAME[city]] + record
                rows.append(row)

    trans = set()       # record IATA code without corresponding ISO-3166-1 code
    for row in rows:
        if row[2] != None and len(row[2]) > 5 and row[2][:5] == "IATA:":
            trans.add(row[2][5:])
    print(trans)

    # save result.csv
    csv_rows = []
    for row in rows:
        csv_rows.append(row[:-1])

    with open("result.csv", "w", encoding='gbk') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        writer.writerows(csv_rows) 

    # save result_agg.csv and draw_data.json
    csv_rows_agg = {}
    draw_data = {}
    addr_key_set = {}
    for row in rows:
        print(row[:-1])
        key = str(row[0]) + str(row[1]) + str(row[2]) + str(row[3]) + str(row[4])   # row[4] for save all chaos record
        if len(row[5]) > 0:                 # traceroute location
            dst_ttl, loc_ttl = row[5].split('->')
            gap = int(dst_ttl) - int(loc_ttl)
            if gap > 1:
                continue
            elif key not in addr_key_set:
                addr_key_set[key] = gap
            elif addr_key_set[key] > gap:
                addr_key_set[key] = gap
            else:
                continue
        elif key in addr_key_set:           # chaos location
            continue
        else:                               # chaos location
            addr_key_set[key] = 100000
            
        csv_rows_agg[key] = row[:-1]
        if row[-1] != None:             # the record has traceroute path
            draw_data[key] = {
                "city": row[0],
                "dst_target": row[1],
                "dst_loc_code": row[2],
                "dst_loc_name": row[3],
                "using_traceroute": row[4],
                "ttl_gap": row[5],
                "time": row[6],
                "paths": row[7],
                "infos": get_ip_infos(row[7])
            }

    csv_rows_agg = list(csv_rows_agg.values())
    draw_data = list(draw_data.values())

    with open("result_agg.csv", "w", encoding='gbk') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        writer.writerows(csv_rows_agg)

    print('csv_rows:' + len(csv_rows))
    print('csv_rows_agg:' + len(csv_rows_agg))
    print('draw_data:' + len(draw_data))
    

    with open("draw_data.json", 'w', encoding='utf-8') as f:
        f.write(json.dumps(draw_data, ensure_ascii=False))

if __name__ == "__main__":
    main()
