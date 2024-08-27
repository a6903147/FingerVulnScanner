import requests
import urllib

def verify(url):
    relsult = {
        'name': '蓝凌OAsysUiComponent 文件存在任意文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Connection':'close'
    }
    vurl = urllib.parse.urljoin(url, "/sys/ui/sys_ui_component/sysUiComponent.do?method=upload")
    try:
        response = requests.get(vurl, headers=headers, timeout=5)
        if response.status_code == 200 and '部件包' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult