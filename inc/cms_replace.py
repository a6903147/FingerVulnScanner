def cms_replace(cms):
    # 定义转换规则的字典
    replacements = {
        # 泛微
        '泛微OA': 'fanwei',
        '泛微OA ecology': 'ecology',
        '泛微-EOffice': 'fanwei',
        'e-ecology 运维管理平台':'fanwei',
        '泛微emp-移动管理平台': 'fanwei',
        'E-ecology-OA': 'ecology',
        '泛微协同办公OA': 'fanwei',
        '泛微e-ecology': 'fanwei',
        '泛微云桥e-Bridge': 'fanwei',
        '泛微e-mobile': 'fanwei',
        # 用友
        '用友NC-Cloud': 'yongyou_nc',
        '用友YonBIP': 'yonyou',
        '用友U8CRM': 'yonyou_u8',
        '用友-UFIDA-NC': 'yonyou',
        '用友-政务财务系统': 'yongyou_government_affairs',
        '用友-移动系统管理': 'yonyou_ufida',
        '用友 NC Cloud': 'yongyou_nc',
        '用友NC': 'yongyou_nc',
        '用友-畅捷通OEM': 'changjietong',
        '用友GRP-U8': 'yonyou_u8',
        '畅捷通-TPlus': 'changjietong',
        'Yonyou-NC': 'yonyou_nc',
        'Yonyou-ERP': 'yonyou',
        'Yonyou-ERP-NC': 'yonyou',
        'Yonyou-GRP-U8': 'yonyou_u8',
        'Yonyou-OA': 'yonyou',
        'Yonyou-U8-cloud': 'yonyou',
        'Yonyou-Uclient': 'yonyou',
        'Yonyou-UFIDA': 'changjietong_ufida',
        'Yonyou-UFIDA-NC': 'yonyou',
        'Yonyou-Seeyon-OA': 'yonyou',
        '用友商战实践平台': 'yonyou',
        '用友erp-nc': 'yonyou',
        '用友U8': 'yonyou_u8',
        '用友ufida': 'yonyou_ufida',
        '用友致远oa': 'yonyou',
        '用友 E-HR': 'yonyou',
        '用友TurboCRM': 'yonyou',
        '用友GRP-U8(财务系统)': 'yonyou',
        '用友优普U8系统': 'yonyou',
        '用友 FE协同办公平台': 'changjietong',
        '畅捷通 T+Cloud': 'changjietong',
        '用友BIP 数据应用服务': 'yonyou',
        # 通达
        '通达OA': 'tongda',
        # 蓝凌
        '蓝凌 OA': 'landray',
        '蓝凌EIS智慧协同平台': 'landray',
        '蓝凌OA(EKP)': 'landray',
        '蓝凌移动办公': 'landray',
        '蓝凌 智慧协同平台': 'landray',


    }

    # 遍历字典，应用转换规则
    for key, value in replacements.items():
        if key in cms:
            cms = cms.replace(key, value)
    return cms
