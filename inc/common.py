from inc import init
from inc import config, output
import argparse, re

'''操作全局变量'''


def _init():
    global _global_dict
    _global_dict = {}


def set_value(key, value):
    _global_dict[key] = value


def get_value(key):
    try:
        return _global_dict[key]
    except:
        return False



'''定义一个 Event 对象用于通知线程退出'''


from threading import Event

exit_event = Event()



'''初始化函数库'''


def get_parser():
    parser = argparse.ArgumentParser(
        usage='python3 pocbomber.py -u http://xxxx -o report.txt',
        description='POC bomber: 基于python3的poc/exp集成框架',
    )
    p = parser.add_argument_group('POC-bomber 的参数')
    p.add_argument("-u", "--url", type=str, help="测试单条url")
    p.add_argument("-f", "--file", type=str, help="测试多个url文件")
    p.add_argument("-o", "--output", type=str, help="报告生成路径(默认不生成报告)")
    p.add_argument("-p", "--poc", type=str, help='指定单个或多个poc进行检测, 直接传入poc文件名, 多个poc用(,)分开')
    p.add_argument("-t", "--threads", type=int, help="指定线程池最大并发数量(默认{0})".format(config.max_threads))
    p.add_argument("-to", "--timeout", type=int, help="指定poc最大超时时间(默认{0}s)".format(config.timeout))
    p.add_argument("-d", "--delay", type=int, help="指定poc休眠时间(默认{0}s)".format(config.delay))
    p.add_argument("--show", action='store_true', help="列所有出poc/exp的详细信息")
    p.add_argument("--attack", action='store_true', help="使用poc文件中的exp进行攻击")
    p.add_argument("--dnslog", action='store_true', help="使用dnslog平台检测无回显漏洞")
    args = parser.parse_args()
    return args


def get_target_list(path):
    target_list = []
    try:
        # 打开文件并读取所有行
        for target in open(path, 'r', errors='ignore').readlines():
            # 去除行尾的换行符
            target = target.replace('\n', '')
            # 检查是否是 HTTP 或 HTTPS URL
            if re.search("https?://.+", target):
                # 去掉 URL 末尾的 /
                if target.endswith('/'):
                    target = target[:-1]
                # 加入列表
                target_list.append(target)
        return target_list
    except:
        # 如果发生异常则返回空列表
        return []


'''加载POC'''
import os, importlib
import platform
from inc import output


# 调用此模块用来加载全部poc

def get_dir_files(base_path):  # 递归调用pocs目录下文件返回每条poc的绝对路径
    file_list = []
    if os.path.isdir(base_path):
        for each_file_or_dir in os.listdir(base_path):
            current_path = os.path.join(base_path, each_file_or_dir)
            if os.path.isfile(current_path) and each_file_or_dir.split('.')[-1] != 'py':  # 只加载py形式的poc文件
                continue
            each_path = get_dir_files(current_path)
            for file in each_path:
                file_list.append(file)
    else:
        file_list.append(base_path)
    return file_list


def path_to_modolepath(path):  # 传入相对路径返回模块导入路径
    if 'Windows' in platform.system():
        path = path.lstrip('\\')
        modole_path = path.replace('\\', '.')
    else:
        path = path.lstrip('/')
        modole_path = path.replace('/', '.')
    modole_path = modole_path.replace('.py', '')
    return modole_path


def get_filename_by_path(path):  # 根据路径获取文件名
    if 'Windows' in platform.system():

        filename = path.split('\\')[-1]
    else:
        filename = path.split('/')[-1]
    return filename


def get_poc_modole_list():  # 调用此函数获取 /pocs 下的全部 poc
    poc_module_list = []
    current_path = os.path.abspath('.')
    pocs_base_path = os.path.join(current_path, 'pocs')
    poc_path_list = get_dir_files(pocs_base_path)
    for poc_path in poc_path_list:
        poc_path = poc_path.replace(current_path, '')
        poc_modole_path = path_to_modolepath(poc_path)
        try:
            poc_module_list.append(importlib.import_module(poc_modole_path))
        except:
            pass
    return poc_module_list


def get_pocinfo_dict():  # 获取pocinfo字典
    pocinfo_dict = {}
    current_path = os.path.abspath('.')
    pocs_base_path = os.path.join(current_path, 'pocs')
    poc_path_list = get_dir_files(pocs_base_path)
    for poc_path in poc_path_list:
        poc_path = poc_path.replace(current_path, '')
        poc_modole_path = path_to_modolepath(poc_path)
        try:
            script_name = get_filename_by_path(poc_path)
            poc_modole = importlib.import_module(poc_modole_path)
            if poc_modole.verify:
                pocinfo_dict[script_name] = poc_modole
        except:
            pass
    return pocinfo_dict


def get_poc_scriptname_list_by_search(path, search_keys_list):  # 定义函数，接收路径和搜索关键字列表作为参数
    search_flag = True if len(search_keys_list) > 0 else False  # 判断是否有搜索关键字，有则设置标志为True
    poc_scriptname_list = []  # 初始化一个空列表，用于存储找到的POC脚本名称
    current_path = os.path.abspath('.')  # 获取当前工作目录的绝对路径
    pocs_base_path = os.path.join(current_path, path)  # 构造POC脚本的基础路径
    poc_path_list = get_dir_files(pocs_base_path)  # 获取基础路径下所有POC文件的路径列表

    if not search_flag:  # 如果没有提供搜索关键字
        for poc_path in poc_path_list:  # 遍历POC文件路径列表
            script_name = get_filename_by_path(poc_path.replace(current_path, ''))  # 从路径中提取文件名
            if script_name in get_value("pocinfo_dict").keys():  # 检查提取的文件名是否在pocinfo_dict字典的键中
                poc_scriptname_list.append(script_name)  # 如果在，则添加到POC脚本名称列表中
        return poc_scriptname_list  # 返回POC脚本名称列表

    # 如果提供了搜索关键字
    for search_key in search_keys_list:  # 遍历搜索关键字列表
        for poc_path in poc_path_list:  # 遍历POC文件路径列表
            script_name = get_filename_by_path(poc_path.replace(current_path, ''))  # 从路径中提取文件名
            # script_path = poc_path.replace(current_path, '')
            # print('search_key:', search_key)
            # print('poc_path:', poc_path)
            if search_key in poc_path:  # 检查搜索关键字是否与文件路径匹配
                if script_name in get_value("pocinfo_dict").keys():  # 检查文件名是否在pocinfo_dict字典的键中
                    output.log_info('成功检测到poc文件: {0}'.format(script_name))  # 如果在，记录信息日志
                    poc_scriptname_list.append(script_name)  # 添加到POC脚本名称列表中
                    search_flag = False  # 找到匹配后，将搜索标志设置为False
                else:
                    search_flag = True  # 如果文件名不在pocinfo_dict字典中，则保持搜索标志为True
                    output.log_error('加载失败: {0}'.format(search_key))  # 记录错误日志
                    break  # 并中断当前循环
        if search_flag:  # 如果循环结束后，搜索标志仍为True
            output.log_warning('未检测到poc文件: {0}'.format(search_key))  # 记录警告日志，表明未找到匹配的POC文件
        search_flag = True  # 重置搜索标志为True，以便下一个搜索关键字的检查
    return poc_scriptname_list  # 返回找到的POC脚本名称列表


def do_path(path):
    base_path = "pocs"
    if path:
        if "\\" in path or "/" in path:
            if 'Windows' in platform.system():
                path = path.replace("/", "\\")
            else:
                path = path.replace('\\', "/")
            if path[0] == "/":
                path = path.lstrip("/")
            return path, []
        else:
            return base_path, path.split(',')
    else:
        return base_path, []
