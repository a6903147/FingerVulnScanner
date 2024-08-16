#!/usr/bin/env python
# coding=utf-8
from inc import init
from inc import thread, common
# 禁用https报错
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings

disable_warnings(InsecureRequestWarning)


def verify(target, script_list):
    thread_pool = thread.ThreadPool()
    for script in script_list:
        thread_pool.add_task(target, script)  # 向线程池中添加当前目标和脚本
    thread_pool.start_threadpool()


def attack(target, script):
    try:
        if common.get_value("pocinfo_dict")[script].attack(target):
            return True
        return False
    except:
        return False
