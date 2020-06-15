# WPA2-PSK算法改进
对家庭wifi认证算法进行改进，防止暴力破解，sta和ap简化为socket的client和server。

主要思想为加密ANonce和SNonce

参考论文《WPA/WPA2-PSK 的安全性分析与改进》，作者吴一尘


## 运行环境
Ubuntu 18.04

## 使用算法
SMS4加密、Michael计算MIC

## 运行
先运行Authenticator，然后运行Supplicant。

P.S.可能存在点小问题，有空回来调通。

## 预期效果
![](https://img-blog.csdnimg.cn/20200615213639969.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3NpbmF0XzQxMTM1NDg3,size_16,color_FFFFFF,t_70)