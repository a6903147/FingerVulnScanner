import chardet
import json
import requests
import warnings
from bs4 import BeautifulSoup

from inc.agent import User_Agent
from inc.icon import get_ico_url, get_hash
# 禁用https报错
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings

disable_warnings(InsecureRequestWarning)

def scan_rule(url):
    warnings.filterwarnings('ignore', category=InsecureRequestWarning)
    headers = User_Agent()
    try:
        response = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=False)
    except Exception as e:
        # print(f"请求 URL 时出错: {url}, 错误: {e}")
        return None, None, None
    content = response.content
    encoding = chardet.detect(content)['encoding']

    try:
        if encoding != 'utf-8':
            html_text = content.decode('gbk')
        else:
            html_text = content.decode(encoding)
    except Exception as e:
        html_text = None

    header_string = str(response.headers)
    status_code = response.status_code

    try:
        soup = BeautifulSoup(html_text, 'html.parser')
        page_title = soup.find("title")
        title = page_title.get_text().strip()
    except Exception as e:
        title = None

    if status_code == 200:
        status_code = status_code
        if title is None or len(title) == 0:
            title = None

    elif status_code == 302:
        redirected_url = response.url
        try:
            redirected_response = requests.get(redirected_url, headers=headers, verify=False, timeout=5)
        except Exception as e:
            # print(f"请求 URL 时出错: {url}, 错误: {e}")
            return None, None, None

        if redirected_response.status_code == 200:
            soup = BeautifulSoup(redirected_response.content, 'html.parser')
            page_title = soup.find('title')

            try:
                title = page_title.get_text().strip()
            except Exception as e:
                title = None

            status_code = status_code

            if title is None or len(title) == 0:
                title = None

    else:
        status_code = status_code
        if title is None or len(title) == 0:
            title = None

    try:
        ico_content = requests.get(url=get_ico_url(url), headers=headers, timeout=5, verify=False).content
        ico_hash = get_hash(ico_content)
    except Exception as e:
        # print(f"请求网站图标时出错: {url}, 错误: {e}")
        ico_hash = None

    with open('inc/finger.json', 'r', encoding='utf-8') as file:
        fingerprint = json.load(file)

    try:
        for fingerprints in fingerprint['fingerprint']:
            cms = fingerprints['cms']
            method = fingerprints['method']
            location = fingerprints['location']
            keywords = fingerprints['keyword']

            if html_text is not None:
                if method == 'keyword' and location == 'body':
                    found_keywords = all(keyword in html_text for keyword in keywords)
                    if found_keywords:
                        return cms, status_code, title

                elif method == 'icon_hash' and location == 'body':
                    found_keywords = all(keyword in ico_hash for keyword in keywords)
                    if found_keywords:
                        return cms, status_code, title

                elif method == 'keyword' and location == 'header':
                    for keyword in keywords:
                        if keyword in header_string:
                            return cms, status_code, title

                elif title is not None:
                    if method == 'keyword' and location == 'title':
                        found_keywords = all(keyword in title for keyword in keywords)
                        if found_keywords:
                            return cms, status_code, title

        return None, status_code, title
    except Exception as e:
        pass
        # print(f"[-] Error occurred during URL identification,Check whether the network is normal: {str(e)}")

#
# def scan_cms(url_list):
#     print('url_list:', url_list)
#     for url in url_list:
#         return scan_rule(url)
