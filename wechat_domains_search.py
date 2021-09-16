#!/usr/bin/env python
# coding=utf-8
# python version 3.7 by
# 批量搜索微信小程序域名
# https://www.hackinn.com/index.php/archives/672/

import requests, time, sys, platform, os


def Get_Domain(X_APP_ID, X_WECHAT_KEY, X_WECHAT_UIN):
    headers = {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 13_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/7.0.11(0x17000b21) NetType/WIFI Language/fr",
        "X-WECHAT-KEY": X_WECHAT_KEY,
        "X-WECHAT-UIN": X_WECHAT_UIN  # 微信两个校验值
    }
    url = "https://mp.weixin.qq.com/mp/waverifyinfo"
    params = "action=get&wx_header=1&appid=" + X_APP_ID
    response = requests.get(url=url, params=params, headers=headers).text
    Response_domain_list = Get_MiddleStr(response, "request_domain_list", "request_domain_list.splice")
    Response_domain_list = Get_MiddleStr(Response_domain_list, "= ", ";")
    exec ("Domain_list.extend(" + Response_domain_list + ")")  # 添加list数组
    time.sleep(8)  # 防止访问频繁，自己调节


def Get_MiddleStr(content, startStr, endStr):  # 获取中间字符串的一个通用函数
    startIndex = content.index(startStr)
    if startIndex >= 0:
        startIndex += len(startStr)
    endIndex = content.index(endStr)
    return content[startIndex:endIndex]


if __name__ == '__main__':
    if platform.system().lower() == 'windows':
        os.system("chcp 65001")  # 切换为utf8编码
    elif platform.system().lower() == 'linux':
        pass
    else:
        print "Unable to run the system,please open in windows、linux"
        exit(-1)
    reload(sys)
    sys.setdefaultencoding('utf-8')  # 解决编码问题
    X_APP_IDS = raw_input("请输入小程序ID(逗号分隔): ")
    X_WECHAT_UIN = raw_input("请输入自己的X-WECHAT-UIN: ")
    X_WECHAT_KEY = raw_input("请输入自己的X-WECHAT-KEY: ")
    X_APPID_LIST = X_APP_IDS.split(",")
    Domain_list = []
    for X_APP_ID in X_APPID_LIST:
        try:
            Get_Domain(X_APP_ID, X_WECHAT_KEY, X_WECHAT_UIN)
        except:
            print X_APP_ID + "的信息获取失败，请检查！"
    Domain_list = list(set(Domain_list))  # list数组去重
    Domain_list = filter(None, Domain_list)  # list数组去空
    print "收集到的域名: " + str(Domain_list)
