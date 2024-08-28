- # FingerVulnScanner

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

  
