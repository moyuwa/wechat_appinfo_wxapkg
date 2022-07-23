#!/usr/bin/env python
# coding=utf-8
# python version 3.7 by
# 批量搜索微信小程序
# https://www.hackinn.com/index.php/archives/672/

import requests, json, sys, platform, os


def Get_Apps(query, number, cookie):
    headers = {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 13_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/7.0.11(0x17000b21) NetType/WIFI Language/fr"}
    url = "https://mp.weixin.qq.com/wxa-cgi/innersearch/subsearch"
    params = "query=" + query + "&cookie=" + cookie + '&subsys_type=1&offset_buf={"page_param":[{"subsys_type":1,"server_offset":0,"server_limit":' + str(
        int(
            number) + 30) + ',"index_step":' + number + ',"index_offset":0}],"client_offset":0,"client_limit":' + number + '}'
    response = requests.post(url=url, params=params, headers=headers).text
    Apps_Json = json.loads(response)
    App_Items = Apps_Json['respBody']['items']
    for App_Item in App_Items:
        App_Item_Json = json.loads(json.dumps(App_Item))  # 重新加载嵌套内容中的json数据
        App_Id = App_Item_Json['appid']
        App_Name = App_Item_Json['nickName']
        App_Id_List.append(App_Id)
        App_Name_List.append(App_Name)


if __name__ == '__main__':
    if platform.system().lower() == 'windows':
        os.system("chcp 65001")#切换为utf8编码
    elif platform.system().lower() == 'linux':
        pass
    else:
        print("Unable to run the system,please open in windows、linux") 
        exit(-1)
    reload(sys)
    sys.setdefaultencoding('utf-8')  # 解决编码问题
    query = raw_input("请输入要搜的微信小程序名称: ")
    number = raw_input("请指定要返回的小程序的数量: ")
    cookie = raw_input("请输入你获取到的Cookie信息: ")
    App_Id_List = []
    App_Name_List = []
    try:
        Get_Apps(query, number, cookie)
        print("返回的小程序名: " + ",".join(App_Name_List)) 
        print("返回的小程序ID: " + ",".join(App_Id_List)) 
    except:
        print("信息获取失败，请检查网络或cookie是否正常！") 
