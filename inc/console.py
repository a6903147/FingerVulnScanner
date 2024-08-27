#!/usr/bin/env python
# coding=utf-8
from inc import init
from inc import run, output, common
from concurrent.futures import ThreadPoolExecutor, as_completed
from inc.common import get_poc_scriptname_list_by_search, get_value
from inc.cms_detected import scan_rule
from inc.cms_replace import cms_replace
import sys

from inc.output import url_color, info_color, log_info


def pocbomber_console():
    """控制台"""
    if common.get_value("delay"):
        common.set_value("max_threads", 1)
    if common.get_value("show"):
        output.show(common.get_value("script_list"))
        sys.exit()
    if not common.get_value("target_list"):
        output.usage()
        sys.exit()

    print('\n[*] starting {0}\n'.format(output.get_time1()))
    output.start_output()
    args = common.get_parser()
    target_list = common.get_value("target_list")
    poc_path, poc_list = common.do_path(args.poc)
    cms_results = {}

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
    log_info('指纹检测完成，开始进行漏洞检。')
    for target, cms in cms_results.items():
        cms_list = []
        if ' ' in cms:
            cms_list = cms.split(' ')
        else:
            cms_list.append(cms)
        script_list = get_poc_scriptname_list_by_search(poc_path, cms_list)
        script_list = list(set(script_list))  # 对获取的poc进行去重
        common.set_value("current_times", 0)
        common.set_value("total_times", len(script_list))
        output.log_info(f"开始对[[{url_color}]{target}[/{url_color}]]进行漏洞检测，已加载 {len(script_list)} 条POC")
        if script_list:
            run.verify(target, script_list)  # 运行poc检测
        else:
            output.log_info('{0}未检测到poc, 跳过漏洞检测'.format(target))
    common.set_value("current_times", common.get_value("total_times") + 1)
    output.close_output()

    print('\n[+] ending {0}\n'.format(output.get_time1()))
