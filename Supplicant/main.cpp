// author: Von
//
// Created by root on 2020/6/9.
//

//socket client
//as the supplicant
//as STA

#include <cstdio>
#include <sys/socket.h>
#include <cstdlib>
#include <netinet/in.h>
#include <cerrno>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include "sm4.h"
#include "mic.h"
using namespace std;

int main(int argc, char **argv)
{

    //创建套接字
    int supSoc = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in autAddr {};
    socklen_t autAddrLen = sizeof(autAddr);
    memset(&autAddr, 0, autAddrLen); //padding with 0
    autAddr.sin_family = AF_INET; //IPv4
    autAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    autAddr.sin_port = htons(7337);

    // 设定PSK，以psk为参数生成nonce，物理地址
    string psk = "VonVonVon";
    //nonce生成准备
    int pskC[9];
    int pskI = 0;
    for(int i = 0; i < psk.length(); i++)
    {
        pskC[i] = psk[i];
        pskI += pskC[i];
    }
    srand(pskI);
    int sNonce = rand();
    sNonce = rand();
    char *supMac = "99:88:77:66:55:44";
    char *autMac = "aa:bb:cc:dd:ee:ff"; //默认可知

    printf("请求者物理地址：%s\n", supMac);

    //向服务器（特定的IP和端口）发起请求
    if(connect(supSoc, (struct sockaddr*)&autAddr, autAddrLen) < 0)
    {
        printf("Connect Error: %s ERRNO :%d\n", strerror(errno), errno);
        exit(1);
    }
    printf("Connect success!\n");

    // 接收ANonce
    char an[0];
    an[9] = '\0';
    if(read(supSoc, an, 9) == -1)
    {
        printf("Read error: %s ERRNO :%d\n", strerror(errno), errno);
        exit(1);
    }
    printf("接收信息：%s", an);
    //解密
    unsigned char sm4key[psk.length()] ;
    for(int i = 0; i < psk.length(); i++)
        sm4key[i] = psk[i];
    int len = 9;
    unsigned char output[len];
    sm4_context ctx;
    sm4_setkey_enc(&ctx, sm4key);
    sm4_crypt_ecb(&ctx, 0, len, reinterpret_cast<unsigned char *>(an), output);
    int aNonce = 0;
    int p = 1;
    for(int i = 8; i >= 0; i--) //char to int
    {
        aNonce += ((an[i]-48) * p);
        p *= 10;
    }
    printf("解密得ANonce：%d\n", aNonce);
    printf("~~~~~~~~~~~~~~~~~\n");

    //计算MIC(ANonce、SNonce、AMac、SMac)
    unsigned char msg[100];
    //计算准备：拼合字段、密钥处理
    sprintf(reinterpret_cast<char *>(msg), "%d%d%s%s", aNonce, sNonce, autMac, supMac);
    unsigned char key[65] ;
    for (int i = 0; i < 65; i++)
        key[i] = psk[i/9];
    key[64] = '\0';
    string supMic = Michael(key, msg, sizeof(msg));

    //计算PTK
    //// PTK = prf - x(PSK, "pair key expansion", min(STA_MAC, AP_MAC) || max(STA_MAC, AP_MAC) || min(ANonce, SNonce) || max(ANonce, SNonce))
    //不进行具体计算只计算参数、拼合表达式
    unsigned char ptk[200];
    int max, min;
    if(aNonce > sNonce)
    {
        max = aNonce;
        min = sNonce;
    }
    else
    {
        max = sNonce;
        min = aNonce;
    }
    //MAC比较略
    sprintf(reinterpret_cast<char *>(ptk), "prf-x(%s, \"pair key expansion\", %s%s%d%d", psk.c_str(), supMac, autMac, min, max);

    //发送SNonce、MIC
    printf("生成SNonce：%d，计算MIC：%s\n", sNonce, supMic.c_str());
    char sn[10];
    p = 10;
    for(int i = 8; i >= 0; i--) //int to char, attention: ascii
    {
        sn[i] = ((sNonce % p)/(p/10)) + 48;
        p *= 10;
    }
    sn[9] = '\0';
    //加密
    sm4_setkey_enc(&ctx, sm4key);
    sm4_crypt_ecb(&ctx, 1, len, reinterpret_cast<unsigned char *>(sn), output);
    printf("加密得：%s，发送中……\n", output);
    if(write(supSoc, reinterpret_cast<const void *>(output), sizeof(output)) == -1)
    {
        printf("Write Error: %s ERRNO :%d\n", strerror(errno), errno);
        exit(1);
    }
    printf("~~~~~~~~~~~~~~~~~\n");

    // 接收密钥安装请求
    char ins[10];
    ins[9] = '\0';
    if(read(supSoc, ins, 9) == -1)
    {
        printf("Read error: %s ERRNO :%d\n", strerror(errno), errno);
        exit(1);
    }
    printf("接收密钥安装请求：%s\n", ins);
    printf("~~~~~~~~~~~~~~~~~\n");

    //提取ptk比较
    //略

    // 发送安装确认
    char *ack = "Install key Acknowledge!";
    if(write(supSoc, ack, strlen(ack)) == -1)
    {
        printf("Write Error: %s ERRNO :%d\n", strerror(errno), errno);
        exit(1);
    }
    printf("确认安装密钥，PTK ＝ %s\n", ptk);

    close(supSoc);
}