import platform
import queue
from inc import common, config, output
from inc.output import log_info


def init_all():
    output.logo()
    log_info('Initializing POC ......')
    args = common.get_parser()
    common._init()
    poc_path, poc_list = common.do_path(args.poc)
    common.set_value("init", True)
    common.set_value("os", "windows" if "Windows" in platform.system() else "linux")
    common.set_value("show_progress", True if config.show_progress else False)
    common.set_value("show", True if args.show else False)  # --show
    common.set_value("output_path", args.output if args.output else config.output_path)  # --output
    common.set_value("max_threads", args.threads if args.threads else config.max_threads)  # --threads
    common.set_value("timeout", args.timeout if args.timeout else config.timeout)  # --timeout
    common.set_value("delay", args.delay if args.delay else config.delay)  # --delay
    common.set_value("target_list", [args.url] if args.url else common.get_target_list(args.file))  # --url,--file
    common.set_value("pocinfo_dict", common.get_pocinfo_dict())  # 初始化poc库，耗时较长
    common.set_value("script_list", common.get_poc_scriptname_list_by_search(poc_path, poc_list))
    common.set_value("total_times", len(common.get_value("script_list")))
    common.set_value("current_times", 0)
    common.set_value("success_times", 0)
    common.set_value("output_queue", queue.Queue())
    common.set_value("success_list", [])
    log_info(f'Initialization complete, with a total of {len(common.get_value("script_list"))} POCs')


if not common.get_value("init"):
    init_all()
