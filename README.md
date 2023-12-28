# wechat_appinfo_wxapkg
 渗透测试：微信小程序信息在线收集，wxapkg源码包内提取信息

20220429 添加云服务密钥匹配、token匹配规则

20231117 按建议添加了hae的规则

20231226 根据反馈，微信小程序搜索接口疑似存在变动，注意使用

python3

**两个在线搜索信息的脚本**

`wechat_app_search.py	批量搜索微信小程序`

`wechat_domains_search.py	批量搜索微信小程序域名`

这两个来源于	https://www.hackinn.com/index.php/archives/672/

**一个搜索wxapkg源码包（反编译后）内敏感信息的脚本**

`wechat_wxapkg_infoget.py	微信小程序源码包wxapkg内部链接提取 v2.0`

内部加入了【findsomething】这个项目的规则，可以匹配手机号、身份证、jwt、url、ip、domain、apikey、user|password等字符串

同时加入了常见的几个apikey匹配规则，大家可修改源码自定义

已经加入了hae的规则，执行后会在当前目录生成infoget1.txt记录结果

