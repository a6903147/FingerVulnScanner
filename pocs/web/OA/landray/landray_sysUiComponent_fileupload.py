import requests
import urllib

def verify(url):
    relsult = {
        'name': '蓝凌OAsysUiComponent 文件存在任意文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Connection':'close'
    }
    vurl = urllib.parse.urljoin(url, "/weaver/")
    try:
        response = requests.get(vurl, headers=headers, timeout=5)
        response_time = response.elapsed.total_seconds()
        if response.status_code == 200 and 'DatabaseName' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult