#ifndef ART_RUNTIME_XUPK_H_
#define ART_RUNTIME_XUPK_H_

#include "art_method.h"
#include "thread.h"
#include <string>
#include <thread>
#include <jni.h>

using namespace std;

namespace art
{
    //void register_android_app_Xupk(JNIEnv *env);
    class Xupk
    {
    public:
        static void xupkFakeInvoke(ArtMethod *artMethod);
        static void unpackAppFlag();

        static uint8_t *getCodeItemEnd(const uint8_t **pData);
        static char *base64Encode(char *str, long str_len, long *outlen);
        static bool getProcessName(char *szProcName);

        static void mapToFile();
        static void dumpClassName(const DexFile *dexFile, const char *feature);
        static void dumpMethod(ArtMethod *artMethod, const char *feature);
        static void dumpDexFile(const DexFile *dexFile, const char *feature);

        static void setThread(Thread *thread);
        static void setMethod(ArtMethod *method);
        static bool isFakeInvoke(Thread *thread, ArtMethod *method);
        static void register_android_app_Xupk(JNIEnv *env);
        
        static bool isCallChainLog();
        static bool isDump();
        static void log(const char* format, ...);
        static inline uint32_t gettid()
        {
            return Thread::Current()->GetTid();
        }
        static string log_time();
        static bool isUnpackFlag;
    private:
        static Thread *xupkThread;
        static ArtMethod *xupkArtMethod;
        static char procName[256];
    };
}

#endif // ART_RUNTIME_XUPK_H_
