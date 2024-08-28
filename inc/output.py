#!/usr/bin/env python
# coding=utf-8
import queue

from inc import init
import time, os
from inc import common, config
import platform, threading
from queue import Empty
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

VERSION = 'v0.1'
OS = platform.system()


def get_time1():
    return time.strftime("@ %Y-%m-%d /%H:%M:%S/", time.localtime())


def get_time2():
    return time.strftime("%H:%M:%S", time.localtime())


def start_output():
    threading.Thread(target=run_output_queue).start()


def close_output():
    exit_event = common.exit_event
    exit_event.set()  # 设置退出事件

    '''
    # 尝试获取 exit_queue 中的值，如果为空则说明队列已经处理完毕
    exit_queue = common.get_value("exit_queue")
    try:
        exit_queue.get(block=False)
    except Empty:
        print("队列为空，无法从 exit_queue 获取数据。")
    except Exception as e:
        print(f"关闭过程中出现异常: {e}")
    '''
    # 等待一段时间以确保 run_output_queue 线程能够响应退出事件并退出
    time.sleep(1)

    output_report(common.get_value("success_list"))


def run_output_queue():
    output_queue = common.get_value("output_queue")
    exit_event = common.exit_event  # 获取退出事件
    while not exit_event.is_set():
        try:
            result = output_queue.get(timeout=1)  # 设置超时以避免无限阻塞
            output_result(result)
        except queue.Empty:
            continue  # 如果队列为空，则继续等待或退出


def put_output_queue(result):
    output_queue = common.get_value("output_queue")
    output_queue.put(result)


def output_result(result):
    current_target, current_script = result['url'], result['script']
    output_path = common.get_value("output_path")
    common.set_value("current_times", common.get_value("current_times") + 1)
    success_times = common.get_value("success_times")
    success_list = common.get_value("success_list")
    percent_num = int(common.get_value('current_times') / common.get_value('total_times') * 100)
    # print('percent_num', percent_num)
    # print('total_times', common.get_value('total_times') * 100)
    percent_str = f"[[{time_color}]{percent_num}%[/]/[{success_color if success_times > 0 else time_color}]{success_times}[/]]" if common.get_value(
        "show_progress") else ""
    try:
        if not result.get("name"):
            log_info(f"检测超时 {percent_str}\[[{timeout_url_color}]{current_target}[/]]  script: {current_script} ")
            return False
        if result['vulnerable']:
            log_success('检测到: {0} from script {1}, 目标: {2} '.format(result['name'], current_script, current_target))
            result['script'] = current_script
            result['url'] = current_target
            common.set_value("success_times", success_times + 1)
            success_list.append(result)
            data_save(output_path, result)
            return result
        else:
            log_info(
                f"正在检测 {percent_str}\[[{url_color}]{current_target.rstrip('/')}[/{url_color}]]  poc: {result['name']}")
            return False
    except:
        log_error(f'poc中产生一个错误  script: {current_script}')
        return False


def output_report(succeed_result):
    output_path = common.get_value("output_path")
    log_info('所有检测任务完成, 即将生成报告......')
    if len(succeed_result) != 0:
        print('----')
        for result in succeed_result:
            for r in result.keys():
                if r == 'name':
                    value = '[!] {0}: {1}'.format(str(r.capitalize()), str(result[r]))
                    console.print(f"[bold color(15)]{value}[/bold color(15)]")
                    value = '    {0}: {1}'.format(str("script".capitalize()), str(result['script']))
                    console.print(f"[bold color(15)]{value}[/bold color(15)]")
                    value = '    {0}: {1}'.format(str("url".capitalize()), str(result['url']))
                    console.print(f"[bold color(15)]{value}[/bold color(15)]")
                elif r == 'script' or r == 'url':
                    pass
                else:
                    value = '      {0}: {1}'.format(str(r.capitalize()), str(result[r]))
                    console.print(f"[bold color(15)]{value}[/bold color(15)]")
        print('----')
        if output_path != '':
            log_info('已将报告写入至 {0} !'.format(os.path.join(os.path.abspath('.'), output_path)))
        else:
            log_warning('程序没有生成任何报告类文件以记录此次任务的数据')
    else:
        log_critical('所有测试已结束但是程序未生成任何报告')


def data_save(output_path, result):
    if output_path == '': return
    report_file = open(output_path, 'a+')
    value = ''
    for r in result.keys():
        if str(r) == 'name':
            value += '[!] {0}: {1}\n'.format(str(r.capitalize()), result['name'])
        else:
            value += '     {0}: {1}\n'.format(str(r.capitalize()), result[r])
    report_file.write(value)
    report_file.close()


from rich.console import Console
from rich.theme import Theme

console = Console(width=2000, theme=Theme(inherit=False))
time_color = "color(6)"
info_color = "color(2)" if "Windows" in OS else "color(8)"
success_color = "color(1)"
warning_color = "color(3)"
critical_color = "color(5)"
error_color = "color(1)"
text_color = "color(7)"
match_color = "bold color(15)"

url_color = "color(12)"
timeout_url_color = "color(3)"


def log_info(mess):
    color = info_color
    console.print(
        f"[{text_color}][[{time_color}]{get_time2()}[/{time_color}]] [[{color}]INFO[/{color}]] {mess}[/{text_color}]")


def log_success(mess):
    color = success_color
    text_color = match_color
    console.print(
        f"[{text_color}][[{time_color}]{get_time2()}[/{time_color}]] [[{color}]SUCCESS[/{color}]] {mess}[/{text_color}]")


def log_warning(mess):
    color = warning_color
    console.print(
        f"[{text_color}][[{time_color}]{get_time2()}[/{time_color}]] [[{color}]WARNING[/{color}]] {mess}[/{text_color}]")


def log_critical(mess):
    color = critical_color
    console.print(
        f"[{text_color}][[{time_color}]{get_time2()}[/{time_color}]] [[{color}]CRITICAL[/{color}]] {mess}[/{text_color}]")


def log_error(mess):
    color = error_color
    console.print(
        f"[{text_color}][[{time_color}]{get_time2()}[/{time_color}]] [[{color}]ERROR[/{color}]] {mess}[/{text_color}]")


def show(script_list):
    pocinfo_dict = {}
    for script in script_list:
        pocinfo_dict[script] = common.get_value("pocinfo_dict")[script]
    poc_info_list = []
    exp_num = 0
    log_info('loading POC/EXP ......')
    for pocinfo in pocinfo_dict.keys():
        poc_modole = pocinfo_dict[pocinfo]
        path = poc_modole.__file__
        try:
            result = poc_modole.verify("http://0.0.0.0")
            name = result['name']
        except:
            continue
        if result.get("attack"):
            attack = result['attack']
            exp_num += 1
        else:
            attack = False
        poc_info = (name, path, attack)
        poc_info_list.append(poc_info)

    for (name, path, attack) in poc_info_list:
        if attack:
            console.print('[bold color(3)][+] Name: {0}\n    Attack: True[/bold color(3)]'.format(name))
        else:
            console.print('[bold color(12)][+] Name: {0}[/bold color(12)]'.format(name))
        print('    Script: {0}'.format(path.split('\\')[-1] if "Windows" in OS else path.split('/')[-1]))
        print('    Path: {0}\n'.format(path))

    print('''\n\t\t\t\t\t\t\t\t\t\tTotal     POC: {0}    EXP: {1}'''.format(len(poc_info_list), exp_num))


def logo1():
    console.print("""
  ______ _                    __      __    _        _____                                 
 |  ____(_)                   \ \    / /   | |      / ____|                                
 | |__   _ _ __   __ _  ___ _ _\ \  / /   _| |_ __ | (___   ___ __ _ _ __  _ __   ___ _ __ 
 |  __| | | '_ \ / _` |/ _ \ '__\ \/ / | | | | '_ \ \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |    | | | | | (_| |  __/ |   \  /| |_| | | | | |____) | (_| (_| | | | | | | |  __/ |   
 |_|    |_|_| |_|\__, |\___|_|    \/  \__,_|_|_| |_|_____/ \___\__,_|_| |_|_| |_|\___|_|   
                  __/ |                                                                    
                 |___/                                                                     
""", style="color(3)")
    console.print(" " * 3 + "{[bold color(3)]https://github.com/a6903147/FingerVulnScanner[/bold color(3)]}")
    console.print("\t " * 5 + f"Version: [color(9)]{VERSION}[/color(9)]")


def logo():
    console.print("""
  ______ _                    __      __    _        _____                                 
 |  ____(_)                   \ \    / /   | |      / ____|                                
 | |__   _ _ __   __ _  ___ _ _\ \  / /   _| |_ __ | (___   ___ __ _ _ __  _ __   ___ _ __ 
 |  __| | | '_ \ / _` |/ _ \ '__\ \/ / | | | | '_ \ \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |    | | | | | (_| |  __/ |   \  /| |_| | | | | |____) | (_| (_| | | | | | | |  __/ |   
 |_|    |_|_| |_|\__, |\___|_|    \/  \__,_|_|_| |_|_____/ \___\__,_|_| |_|_| |_|\___|_|   
                  __/ |                                                                    
                 |___/                                                                     
""", style="color(3)")
    console.print(" " * 3 + "{[bold color(3)]https://github.com/a6903147/FingerVulnScanner[/bold color(3)]}")
    console.print("\t " * 5 + f"Version: [color(9)]{VERSION}[/color(9)]\n")


def usage():
    print('''
        用法:
                获取poc/exp信息:   python3 FingerVulnScanner.py --show
                单目标检测:        python3 FingerVulnScanner.py -u http://xxx.xxx.xx 
                批量检测:          python3 FingerVulnScanner.py -f url.txt -o report.txt
                指定poc检测:       python3 FingerVulnScanner.py -f url.txt --poc="xxx.py"
        参数:
                -u  --url      目标url
                -f  --file     指定目标url文件   
                -o  --output   指定生成报告的文件(默认{0})
                -t  --thread   指定线程池最大并发数量(默认{1})
                -to --timeout  指定poc最大超时时间(默认{2}s)
                -d  --delay    指定poc休眠时间(默认{3}s)
                --show         展示poc/exp详细信息'''.format(
        "不生成" if len(config.output_path) == 0 else config.output_path,
        config.max_threads, config.timeout,
        config.delay,
    ), end='')
