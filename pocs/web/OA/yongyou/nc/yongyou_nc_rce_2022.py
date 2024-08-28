import requests
import urllib, re

def verify(url):
    relsult = {
        'name': '用友NC bsh.servlet.BshServlet 命令执行(2022HVV)',
        'vulnerable': False,
        'url': url
    }
    timeout = 3
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    vurl = urllib.parse.urljoin(url, '/servlet//~ic/bsh.servlet.BshServlet')
    try:
        rep = requests.get(vurl, headers=headers, verify=False, timeout=timeout)
        if rep.status_code == 200 and re.search('BeanShell Test Servle', rep.text):
            relsult['vulnerable'] = True
            relsult['vurl'] = vurl
        return relsult
    except:
        return relsult
