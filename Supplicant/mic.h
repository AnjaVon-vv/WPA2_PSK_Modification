// author: Von
//
// Created by root on 2020/6/9.
//

#ifndef SM4_MIC_H
#define SM4_MIC_H

#include <string>
#include <sstream>
#include <cstring>
using namespace std;

unsigned long rol17(unsigned long w)    // rotate left 17
{
    register unsigned long t, q;
    t = w << 17;
    q = (w >> 15);
    return(t|q);
}

unsigned long rol3(unsigned long w)    // rotate left 3
{
    register unsigned long t, q;
    t = w << 3;
    q = (w >> 29);
    return(t|q);
}


unsigned long ror2(unsigned long w)    // rotate right 2
{
    register unsigned long t, q;
    t = (w >> 2);
    q = w << 30;
    return(t|q);
}


static unsigned long getw(unsigned char *cp)
{
    register unsigned long t;

    t = 0;
    t = *cp++;
    t |= (*cp++)<<8;
    t |= (*cp++)<<16;
    t |= (*cp++)<<24;
    return(t);
}

void putw(unsigned long w, unsigned char *cp)
{

    *cp++ = (short int)w; // MS compiler forces use of 0xff
    *cp++ = (short int)(w>>8);
    *cp++ = (short int)(w>>16);
    *cp++ = (short int)(w>>24);
    return;
}


string longToString(long l)
{
    ostringstream os;
    os<<l;
    string result;
    istringstream is(os.str());
    is>>result;
    return result;
}


// Michael integrity function
// pads the buffer (s) with up to 7 bytes
// if h is non-null, it is prepended to the buffer.
// The function appends an additional 8 bytes of Michael
// returns buffer len (payload+Michael)
//
string Michael(unsigned char *key, unsigned char *s, int dlen)
{
    register unsigned long M;
    unsigned long L, R;
    int len = dlen;
    register unsigned char *sp, *cp;

    L = getw(key);  // L = *LL; R = *RR;
    R = getw(key+4);

    sp = s;
    sp[len++] = 0x5a;   // message padding
    sp[len++] = 0;    // 4 required
    sp[len++] = 0;
    sp[len++] = 0;
    sp[len++] = 0;
    while (len&0x3) {   // word aligned
        sp[len++] = 0;
    }

    sp = s;
    unsigned long num = 4294967296;
    while (len > 0) {
        M = getw(sp);    // M = *mp++; len -= 4;
        sp+=4; len -= 4;

        L ^= M;    // Michael block function
        R = R ^ rol17(L);
        L = (L + R) % num;
        R ^= ((L & 0xff00ff00)>>8)|((L & 0x00ff00ff) << 8);
        L = (L + R) % num;
        R ^= rol3(L);
        L = (L + R) % num;
        R ^= ror2(L);
        L = (L + R) % num;
        R %= num;
    }
    cp = s+dlen;
    putw(L, (unsigned char *)cp);
    cp = s+dlen+4;
    putw(R, (unsigned char *)cp);

    string res;
    stringstream ss;
    ss << longToString(L) << longToString(R);
    res=ss.str();

    return res;
}

#endif //SM4_MIC_H
