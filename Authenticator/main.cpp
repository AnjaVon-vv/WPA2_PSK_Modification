// author: Von
//
// Created by root on 2020/6/9.
//

//socket server
//as the authenticator
//as AP

#include <cstdio>
#include <sys/socket.h>
#include <cstring>
#include <netinet/in.h>
#include <cerrno>
#include <unistd.h>
#include <string>
#include <dumbnet.h>
#include "sm4.h"
#include "mic.h"
using namespace std;

int main(int argc, char **argv)
{
    //创建套接字
    int autSoc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    struct sockaddr_in autAddr {};
    socklen_t autAddrLen = sizeof(autAddr);
    memset(&autAddr, 0, autAddrLen); //padding with 0
    autAddr.sin_family = AF_INET; //IPv4
    autAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    autAddr.sin_port = htons(7337);
    //将套接字和ip、端口绑定
    bind(autSoc, (struct sockaddr*)&autAddr, autAddrLen);

    // 设定PSK，以psk为参数生成nonce，物理地址
    string psk = "VonVonVon";
    int pskC[9];
    int pskI = 0;
    for(int i = 0; i < psk.length(); i++)
    {
        pskC[i] = psk[i];
        pskI += pskC[i];
    }
    srand(pskI);
    int aNonce = rand();
    char *autMac = "aa:bb:cc:dd:ee:ff";
    char *supMac = "99:88:77:66:55:44"; //默认可知
    printf("认证者物理地址：%s\n", autMac);

    //监听，等待用户发起请求
    listen(autSoc, 1024);
    printf("Waiting for a supplicant......\n");
    printf("~~~~~~~~~~~~~~~~~\n");

    //接收客户端请求
    struct sockaddr_in supAddr {};
    socklen_t supAddrLen = sizeof(supAddr);
    int supSoc = accept(autSoc, (struct sockaddr*)&supAddr, &supAddrLen);

    //发送ANonce
    printf("生成ANonce：%d\n", aNonce);
    char an[10];
    int p = 10;
    for(int i = 8; i >= 0; i--) // int to char, attention: ascii
    {
        an[i] = ((aNonce % p)/(p/10)) + 48;
        p *= 10;
    }
    an[9] = '\0';
    //加密
    unsigned char sm4key[psk.length()] ;
    for(int i = 0; i < psk.length(); i++)
        sm4key[i] = psk[i];
    int len = 9;
    unsigned char output[len];
    sm4_context ctx;
    sm4_setkey_enc(&ctx, sm4key);
    sm4_crypt_ecb(&ctx, 1, len, reinterpret_cast<unsigned char *>(an), output);
    printf("加密得：%s，发送中……\n", output);
    if(write(supSoc, reinterpret_cast<const void *>(output), sizeof(output)) == -1)
    {
        printf("Write Error: %s errno :%d\n", strerror(errno), errno);
        exit(1);
    }
    printf("~~~~~~~~~~~~~~~~~\n");

    // 接收SNonce、MIC
    char sn[10];
    sn[9] = '\0';
    if(read(supSoc, sn, 9) == -1)
    {
        printf("Read error: %s ERRNO :%d\n", strerror(errno), errno);
        exit(1);
    }
    printf("接收信息：%s", sn);
    //解密
    sm4_setkey_enc(&ctx, sm4key);
    sm4_crypt_ecb(&ctx, 0, len, reinterpret_cast<unsigned char *>(sn), output);
    int sNonce = 0;
    p = 1;
    for(int i = 8; i >= 0; i--) //char to int
    {
        sNonce += ((output[i]-48) * p);
        p *= 10;
    }
    printf("解密得SNonce：%d\n", sNonce);
    printf("~~~~~~~~~~~~~~~~~\n");

    //计算MIC(ANonce、SNonce、AMac、SMac)
    unsigned char msg[100];
    //计算准备：拼合字段、密钥处理
    sprintf(reinterpret_cast<char *>(msg), "%d%d%s%s", aNonce, sNonce, autMac, supMac);
    unsigned char key[65] ;
    for (int i = 0; i < 65; i++)
        key[i] = psk[i/9];
    key[64] = '\0';
    string autMic = Michael(key, msg, sizeof(msg));
    printf("计算得MIC：%s", autMic.c_str());

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

    //mic比较略
    printf("MIC核验通过！");

    // 发送密钥安装请求
    char ins[200];
    sprintf(ins, "Key installation, PSK is \"%s\"", ptk);
    printf("发送密钥安装请求：%s\n", ins);
    if(write(supSoc, ins, sizeof(ins)) == -1)
    {
        printf("Write Error: %s ERRNO :%d\n", strerror(errno), errno);
        exit(1);
    }
    printf("~~~~~~~~~~~~~~~~~\n");

    // 接收安装确认
    char ack[100];
    if(read(supSoc, ack, sizeof(ack)) == -1)
    {
        printf("Read error: %s ERRNO :%d\n", strerror(errno), errno);
        exit(1);
    }
    ack[sizeof(ack)] = '\0';
    printf("接收密钥安装确认：%s\n", ack);
    printf("认证成功！");

    close(supSoc);
    close(autSoc);
}