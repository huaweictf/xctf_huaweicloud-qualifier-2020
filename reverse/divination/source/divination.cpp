#include <jni.h>
#include <string>
#include<boost/multiprecision/cpp_int.hpp>

typedef boost::multiprecision::uint256_t uint256;
using namespace std;
unsigned char dst[32] = {0x34,0x39,0xa7,0x64,0xbd,0x4d,0x7d,0x12,0x5e,0xb8,0x7f,0xb4,0x33,0x2a,0x1d,0xe0,0x77,0x6c,0x00,0xcd,0x18,0xa4,0x31,0x4d,0xb0,0xa7,0xdc,0x83,0x43,0x35,0x0f,0x8f};
uint256 lrol(uint256 c,unsigned int b)
{
        uint256 left=c<<b;
        uint256 right=c>>(256-b);
        uint256 temp=left|right;
        return temp;
}

uint256  lror(uint256 c,unsigned int b)
{
        uint256 right =c>>b;
        uint256 left =c<<(256-b);
        uint256 temp=left|right;
        return temp;
}

__attribute__((__constructor__)) static void pp_init() {
    uint64_t key=0x687970657270776e;
    uint64_t *p;
    p = (uint64_t *)dst;
    for(int i=0;i<4;i++)
        p[i]^=key;
}

extern "C" JNIEXPORT bool JNICALL
Java_mystery_fortune_telling_MainActivity_divination(
        JNIEnv* env,
        jobject /* this */,
        jstring input) {
        const char *ptr = env->GetStringUTFChars(input, 0);
        int i,j,k=1;

        uint256 n=-1;
        int len = strlen(ptr);
        memset(&n,0,32);
        memcpy(&n, ptr, min(len,32));
        uint256 m=n;
        for(i=3;i<129;i+=2){
                for(j=3;j<12;j+=2){
                        if(!(i%j))
                                goto next;
                }
                if(k) {

                        m^=lrol(n, i);
                } else {

                        m^=lror(n, i);
                }

                k = !k;
            next: len++;
        }
        env->ReleaseStringUTFChars(input, ptr);
        if(!memcmp(&m,dst,32)){
                return true;
        }
        return false;
}
