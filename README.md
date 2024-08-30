# FingerVulnScanner

**FingerVulnScanner** 是一个根据目标系统指纹进行专项漏洞扫描的工具，旨在大量资产里快速取得外网权限。该工具使用 CMS 对应的 POC 进行扫描，减少误报并且减小对目标系统的压力。

## 开发场景

1. 现有扫描器在对目标站点进行扫描时，将poc库里的所有漏洞都进行扫描。这样做效率低、增加服务器负担并且被蓝队发现的概率更高。
2. 目前有针对指纹扫描的工具，也有针对漏洞扫描的工具。但是还没有人把这两种工具的功能合并到一起，根据目标的系统指纹针对性的进行漏洞扫描。

## 介绍

指纹识别模块基于[chunsou](https://github.com/Funsiooo/chunsou)进行开发，漏洞扫描框架基于[POC-bomber](https://github.com/tr0uble-mAker/POC-bomber)，指纹库为[EHole](https://github.com/EdgeSecurityTeam/EHole)。



## 工作流程

**1. 初始化** 遍历 `pocs` 文件夹下的每一个子文件夹，获取 `.py` 文件格式的 poc。 

**2. 指纹识别** 根据 `./inc/finger.json` 中的指纹库，通过 `inc.cms_detected.scan_rule()` 函数对目标站点进行指纹识别，并返回 cms 名称。

```python
    log_info('开始对所有目标进行指纹探测，共计{0}个目标!'.format(len(target_list)))
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_target = {executor.submit(scan_rule, target): target for target in target_list}
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                cms, status_code, title = future.result()
                if cms:
                    output.log_info(
                        f"检测到 [[{url_color}]{target}[/{url_color}]]的指纹为 [[{info_color}]{cms}[/{info_color}]]")
                    cms = cms_replace(cms)
                else:
                    output.log_info(f" [[{url_color}]{target}[/{url_color}]]未匹配到指纹。")
            except Exception as exc:
                pass
                # print(f'{target} 生成异常: {exc}')
            else:
                if cms:
                    cms_results[target] = cms
```

 **3. poc 匹配** 通过 `./inc/cms_replace.py` 将获取到的 CMS 名称和 poc 进行对应（例如: `用友NC-Cloud`-->`yongyou_nc`），并根据 poc 文件的完整路径名进行匹配。只要 `yongyou_nc` 存在于 `D:\FingerVulnScanner\pocs\web\OA\yongyou\nc\yongyou_nc-find-web_fileread.py` 中就认为匹配成功。

 **4. 漏洞检测** 对匹配到 poc 的目标，调用 poc 文件内的 `verify()` 方法进行漏洞检测，如存在漏洞则返回 `True` 并返回漏洞路径。

## 代码执行过程

1. 运行`FingerVulnScanner.py`
2. `init.py`开始初始化一些全局变量，比如每个POC的地址、POC数量等
3. `FingerVulnScanner.py`调用`console.py`进入到主流程：
   - 调用`inc.cms_detected.scan_rule()`进行指纹识别，在控制台打印返回的指纹结果，同时利用`cms = cms_replace(cms)`来进行cms名称与poc路径匹配的转化，之后返回`cms_results`（包含探测到指纹的url和对应的cms名称）
   - 等待所有url指纹识别完成之后，遍历`cms_results`将其中的每一个url和对应的通过`inc.run.verify`提交到线程池进行漏洞检测
4. 通过`inc/output.py`来实时打印进度

```
FingerVulnScanner.py-->inc/init.py-->inc/console.py-->inc.cms_detected.scan_rule-->inc.run.verify
```

## 用法


- 获取poc/exp信息:
  ```
  python3 FingerVulnScanner.py --show
  ```
- 单目标检测:
  ```
  python3 FingerVulnScanner.py -u http://xxx.xxx.xx
  ```
- 批量检测:
  ```
  python3 FingerVulnScanner.py -f url.txt -o report.txt
  ```
- 指定poc检测:
  ```
  python3 FingerVulnScanner.py -f url.txt --poc="xxx.py"
  ```

**参数**

- `-u`, `--url`      目标url
- `-f`, `--file`     指定目标url文件
- `-o`, `--output`   指定生成报告的文件(默认不生成)
- `-t`, `--thread`   指定线程池最大并发数量(默认30)
- `-to`, `--timeout` 指定poc最大超时时间(默认13s)
- `-d`, `--delay`    指定poc休眠时间(默认0s)
- `--show`           展示poc/exp详细信息



## 其他工具

### generate_script

将请求包写到post.txt内，然后运行generate_script.py就会根据请求包生成对应的python的request请求。
![image-20240827155939112](https://github.com/user-attachments/assets/dbcd0d43-494d-4179-aa4f-d6cbce51f5f1)

![image-20240827155929423](https://github.com/user-attachments/assets/f5f0cfd9-f205-4e81-b076-c9ffc56a6658)


```python
import os

def generate_python_script_from_file(file_path):
    with open(file_path, 'r') as file:
        request_data = file.read()
    
    lines = request_data.strip().split('\n')
    
    if len(lines) < 1:
        print("Invalid request data")
        return
    
    method_line_parts = lines[0].split()
    if len(method_line_parts) < 3:
        print("Invalid request line")
        return
    
    method, path, _ = method_line_parts
    host = ''
    headers = {}
    body = None

    # 解析头部和主体
    for index, line in enumerate(lines[1:], start=1):
        if line.startswith('Host:'):
            host = line.split(': ')[1] if ': ' in line else ''
        elif ': ' in line:
            key, value = line.split(': ', 1)
            headers[key.strip()] = value.strip()
        elif line == '':
            body = '\n'.join(lines[index+1:])
            break

    url = f"http://{host}{path}"
    headers_str = ',\n    '.join([f"'{key}': '{value}'" for key, value in headers.items()])

    if method.upper() == 'POST' and body:
        script_content = f"""import requests

url = '{url}'
headers = {{
    {headers_str}
}}
data = '''{body}'''

response = requests.post(url, headers=headers, data=data)

print(response.text)
"""
    else:
        script_content = f"""import requests

url = '{url}'
headers = {{
    {headers_str}
}}

response = requests.get(url, headers=headers)

print(response.text)
"""

    with open('send_request.py', 'w') as f:
        f.write(script_content)

    print('Python script generated: send_request.py')

# Example usage
file_path = 'post.txt'
generate_python_script_from_file(file_path)
```

### JSON指纹提取

根据设置的指纹关键字，从finger文件夹中的所有指纹库中搜寻对应指纹，并根据指纹的keyword进行去重。

```python
import os
import json

# 设置指纹库所在的文件夹路径
finger_folder_path = 'finger'

# 定义匹配关键字的列表
keywords_to_match = ['通达OA', 'cology', '泛微','用友','畅捷通','Yonyou','蓝凌']  # 根据需要添加更多关键字

# 用于存储所有指纹数据
all_fingerprints = []

# 遍历指定文件夹
for filename in os.listdir(finger_folder_path):
    if filename.endswith('.json'):  # 确保文件是JSON格式
        with open(os.path.join(finger_folder_path, filename), 'r', encoding='utf-8') as file:
            try:
                data = json.load(file)
                all_fingerprints.extend(data.get('fingerprint', []))  # 将指纹数据添加到列表中
            except json.JSONDecodeError as e:
                print(f"Error reading {filename}: {e}")

# 提取包含任一关键字的指纹数据
matched_fingerprints = [fp for fp in all_fingerprints if any(kw in fp.get('cms', '') for kw in keywords_to_match)]

# 根据keyword去重
unique_matched_fingerprints = {}
for fp in matched_fingerprints:
    # 将keyword列表转换成元组，作为去重的依据
    keyword_tuple = tuple(fp.get('keyword', []))
    if keyword_tuple not in unique_matched_fingerprints:
        unique_matched_fingerprints[keyword_tuple] = fp

# 准备写入新的JSON文件，只包含去重后的数据
matched_fingerprints_json = {"fingerprint": list(unique_matched_fingerprints.values())}

# 将去重后的指纹保存到新文件中
with open('matched_fingerprints.json', 'w', encoding='utf-8') as new_file:
    json.dump(matched_fingerprints_json, new_file, indent=4, ensure_ascii=False)

print(f"完成提取并去重指纹，共计{len(list(unique_matched_fingerprints.values()))}条指纹数据，存储在'matched_fingerprints.json'文件中。")

```

## 关于POC编写

​	格式：均为cms名称-漏洞点-漏洞类型.py 例如:`yongyou_nc-find-web_fileread.py`

​	**编写流程**

1. 根据cms类型在对应的文件夹下创建py文件，并复制poc_model.txt的内容到你新建的poc.py文件内
2. 填写relsult.name为漏洞名称，以及16行的requests的请求方法（如果默认填写get方法，可能会在应该使用post请求的地方忘记修改）
![image-20240829162440350](https://github.com/user-attachments/assets/f3b270fe-9fe1-4c15-b567-1ccab43d1d56)

3. 使用`generate_script/generate_script.py`工具根据请求包生成对应的request请求，主要是对于header的处理，如果手动写header会比较繁琐。
4. 根据生成的`send_request.py`的内容，填写编写POC的header和data（如果存在）
5. 根据每个漏洞的特征，填写对应的判断条件，如`if response.status_code == 200 and 'DatabaseName' in response.text:`
6. 对于延时注入漏洞，不能直接采取判断`response.elapsed.total_seconds() > 5`这种方法，在多线程的测试中，只依靠响应时间来判断会导致较高的误报率，可以佐以响应码为500或者response.body里特有的一些内容结合起来判断。
7. 在编写时，可以调用`inc/generate_random.py`中的`generate_random_str()`和`generate_random_number()`来生成一定位数的随机字符或数字，可以用来做文件上传漏洞文件名或其他漏洞的一些字段

## 更新记录

- 2024年8月28日

​	创建项目，并且添加泛微、用友系统的部分poc

- 2024年8月30日

  添加通达、蓝凌、亿赛通的部分poc，所有poc共计154个。

[![](https://starchart.cc/a6903147/FingerVulnScanner.svg)](https://starchart.c/a6903147/FingerVulnScanner)
