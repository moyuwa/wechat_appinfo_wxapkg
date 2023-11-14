#!/usr/bin/env python3
# coding=utf-8
# python version 3.7 by-6time
# 结合 https://github.com/momosecurity/FindSomething 规则

import os, sys, re

relist = {
    # ======== 自定义 规则 ========
    "httplist": "\"http.://.*?\"", "urllist": "\".*?[^http]/.*?\\?.*?=\"", "apikeylist": "api.*?key.*?=",
    "apikeylist": "api.*?key.*?:",
    "userpwdlist": "user.*?=\".*?\"", "userpwdlist": "passw.*?=\".*?\"",
    "accesskey": "access.*?key.*?=", "accesskey": "access.*?key.*?:",
    "tokenkey": "token.*?key.*?=", "tokenkey": "token.*?key.*?:",
    "apipath": "\"[/|]api.*?/.*?[/|]\"", "secret": "secret[id|key].*?=.*?\".*?\"",
    "secret": "secret[id|key].*?:.*?\".*?\"",
    # ======== findsomething 规则 ========
    "sfz": "['\"]((\d{8}(0\d|10|11|12)([0-2]\d|30|31)\d{3}$)|(\d{6}(18|19|20)\d{2}(0[1-9]|10|11|12)([0-2]\d|30|31)\d{3}(\d|X|x)))['\"]",
    "mobile": "['\"](1(3([0-35-9]\d|4[1-8])|4[14-9]\d|5([\d]\d|7[1-79])|66\d|7[2-35-8]\d|8\d{2}|9[89]\d)\d{7})['\"]",
    "mail": "['\"][a-zA-Z0-9\._\-]*@[a-zA-Z0-9\._\-]{1,63}\.((?!js|css|jpg|jpeg|png|ico)[a-zA-Z]{2,})['\"]",
    "ip_port": "['\"]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}['\"]",
    "ip_port": "['\"]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{1,5}['\"]",
    "domain": "['\"][a-zA-Z0-9\-\.]*?\.(xin|com|cn|net|com.cn|vip|top|cc|shop|club|wang|xyz|luxe|site|news|pub|fun|online|win|red|loan|ren|mom|net.cn|org|link|biz|bid|help|tech|date|mobi|so|me|tv|co|vc|pw|video|party|pics|website|store|ltd|ink|trade|live|wiki|space|gift|lol|work|band|info|click|photo|market|tel|social|press|game|kim|org.cn|games|pro|men|love|studio|rocks|asia|group|science|design|software|engineer|lawyer|fit|beer|我爱你|中国|公司|网络|在线|网址|网店|集团|中文网)['\"]",
    "path": "['\"]\/[^\/\>\< \)\(\{\}\,\'\"\\]([^\>\< \)\(\{\}\,\'\"\\])*?['\"]",
    "url": "['\"](([a-zA-Z0-9]+:)?\/\/)?[a-zA-Z0-9\-\.]*?\.(xin|com|cn|net|com.cn|vip|top|cc|shop|club|wang|xyz|luxe|site|news|pub|fun|online|win|red|loan|ren|mom|net.cn|org|link|biz|bid|help|tech|date|mobi|so|me|tv|co|vc|pw|video|party|pics|website|store|ltd|ink|trade|live|wiki|space|gift|lol|work|band|info|click|photo|market|tel|social|press|game|kim|org.cn|games|pro|men|love|studio|rocks|asia|group|science|design|software|engineer|lawyer|fit|beer|我爱你|中国|公司|网络|在线|网址|网店|集团|中文网)(\/.*?)?['\"]",
    "jwt": "['\"'](ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}|ey[A-Za-z0-9_\/+-]{10,}\.[A-Za-z0-9._\/+-]{10,})['\"']",
    "algorithm": "\W(base64\.encode|base64\.decode|btoa|atob|CryptoJS\.AES|CryptoJS\.DES|JSEncrypt|rsa|KJUR|$\.md5|md5|sha1|sha256|sha512)[\(\.]",
    # ======== HEA 规则 ========
    # https://raw.githubusercontent.com/gh0stkey/HaE/gh-pages/Rules.yml
    "Shiro": "(=deleteMe|rememberMe=)",
    "JSON Web Token": "(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}|eyJ[A-Za-z0-9_\/+-]{10,}\.[A-Za-z0-9._\/+-]{10,})",
    "Swagger UI": "((swagger-ui.html)|(\"swagger\":)|(Swagger UI)|(swaggerUi)|(swaggerVersion))",
    "Ueditor": "(ueditor\.(config|all)\.js)",
    "RCE Paramters": "((cmd=)|(exec=)|(command=)|(execute=)|(ping=)|(query=)|(jump=)|(code=)|(reg=)|(do=)|(func=)|(arg=)|(option=)|(load=)|(process=)|(step=)|(read=)|(function=)|(feature=)|(exe=)|(module=)|(payload=)|(run=)|(daemon=)|(upload=)|(dir=)|(download=)|(log=)|(ip=)|(cli=))",

    "Java Deserialization": "(javax\.faces\.ViewState)",
    "Debug Logic Parameters": "((access=)|(adm=)|(admin=)|(alter=)|(cfg=)|(clone=)|(config=)|(create=)|(dbg=)|(debug=)|(delete=)|(disable=)|(edit=)|(enable=)|(exec=)|(execute=)|(grant=)|(load=)|(make=)|(modify=)|(rename=)|(reset=)|(root=)|(shell=)|(test=)|(toggl=))",

    "URL As A Value": "(=(https?)(://|%3a%2f%2f))",
    "Upload Form": "(type=\"file\")",
    "DoS Paramters": "((size=)|(page=)|(num=)|(limit=)|(start=)|(end=)|(count=))",
    "Email": "(([a-z0-9][_|\.])*[a-z0-9]+@([a-z0-9][-|_|\.])*[a-z0-9]+\.((?!js|css|jpg|jpeg|png|ico)[a-z]{2,}))",
    "Chinese IDCard": "'[^0-9]((\d{8}(0\d|10|11|12)([0-2]\d|30|31)\d{3}$)|(\d{6}(18|19|20)\d{2}(0[1-9]|10|11|12)([0-2]\d|30|31)\d{3}(\d|X|x)))[^0-9]'",
    "Chinese Mobile Number": "'[^\w]((?:(?:\+|00)86)?1(?:(?:3[\d])|(?:4[5-79])|(?:5[0-35-9])|(?:6[5-7])|(?:7[0-8])|(?:8[\d])|(?:9[189]))\d{8})[^\w]'",
    "Internal IP Address": "'[^0-9]((127\.0\.0\.1)|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3}))'",
    "MAC Address": "(^([a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5})|[^a-zA-Z0-9]([a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5}))",
    "Chinese Bank Card ID": "'[^0-9]([1-9]\d{12,18})[^0-9]'",
    "Cloud Key": "((accesskeyid)|(accesskeysecret)|(LTAI[a-z0-9]{12,20}))",
    "Windows File/Dir Path": r'[^\w](([a-zA-Z]:\\(?:\w+\\?)*)|([a-zA-Z]:\\(?:\w+\\)*\w+\.\w+))',
    "Password Field": "((|'|\")([p](ass|wd|asswd|assword))(|'|\")(:|=)( |)('|\")(.*?)('|\")(|,))",
    "Username Field": "((|'|\")(([u](ser|name|ame|sername))|(account))(|'|\")(:|=)( |)('|\")(.*?)('|\")(|,))",
    "WeCom Key": "([c|C]or[p|P]id|[c|C]orp[s|S]ecret)",
    "JDBC Connection": "(jdbc:[a-z:]+://[a-z0-9\.\-_:;=/@?,&]+)",
    "Authorization Header": "((basic [a-z0-9=:_\+\/-]{5,100})|(bearer [a-z0-9_.=:_\+\/-]{5,100}))",
    "Github Access Token": "([a-z0-9_-]*:[a-z0-9_\-]+@github\.com*)",
    "Sensitive Field": "((|'|\")([\w]{0,10})((key)|(secret)|(token)|(config)|(auth)|(access)|(admin))(|'|\")(:|=)(|)('|\")(.*?)('|\")(|,))",
    "Linkfinder": "(?:\"|')(((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\.[a-zA-Z]{2,}[^\"']{0,})|((?:/|\.\./|\./)[^\"'><,;|*()(%%$^/\\\[\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^\"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^\"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:\w)(?:[\?|#][^\"|']{0,}|)))(?:\"|')",

    "Source Map": "(\.js\.map)",
    # "HTML Notes":"(<!--[\s\S]*?-->)", // 这个误报太多了，有需要取消注释
    "Create Script": "(createElement\(\"script\"\))",
    "URL Schemes": "(?![http]|[https])(([-A-Za-z0-9]{1,20})://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|])",
}


# 枚举js文件
def jspath(rootDir):
    jss = []
    for root, dirs, files in os.walk(rootDir):
        for file in files:
            docname = os.path.join(root, file)
            if docname[-4:].find(".js") != -1:
                # print(docname)
                jss.append(docname)
    return jss


# 匹配关键字符串
def rekeystring(jss=[]):
    search_data = {}
    for key, value in relist.items():
        search_data[key] = []
    for js in jss:
        with open(js, "r", encoding="utf-8") as f:
            txt = f.read()
            for key, value in relist.items():
                # print(key, value)
                search_data[key].append(re.findall(value, txt))
                # print(search_data)
    return search_data


# 信息输出
def outprintf(httplist=[]):
    with open("httplist.txt", "a",encoding="utf-8") as f:
        for http1 in httplist:
            for http2 in http1:
                if isinstance(http2, tuple):
                    for s1 in http2:
                        f.write(str(s1).strip("\"").rstrip("\""))
                else:
                    s1 = str(http2).strip("\"").rstrip("\"")
                    f.write(s1)
    for http1 in httplist:
        for http2 in http1:
            if isinstance(http2, tuple):
                for s1 in http2:
                    print(str(s1).strip("\"").rstrip("\""))
            else:
                s1 = str(http2).strip("\"").rstrip("\"")
                print(s1)


def domain():
    jss = jspath(sys.argv[1])  # sys.argv[1] "./wxapkg"
    search_data = rekeystring(jss)
    for key, value in relist.items():
        print("===" * 5, key, "===" * 5)
        with open("httplist.txt", "a", encoding="utf-8") as f:
            f.write(str("===" * 5+ key+"===" * 5+"\n"))
        outprintf(search_data[key])


if __name__ == "__main__":
    print("""
    微信小程序源码包wxapkg内部链接提取 v2.0
    py -3 wechat_wxapkg_infoget.py [wxapkg dir]
    """)
    # _ok = input('已确认更改信息?(y/n)')
    # os.system('pause')
    domain()
