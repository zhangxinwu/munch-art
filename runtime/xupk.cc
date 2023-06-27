#include "xupk.h"
#include <sys/stat.h>
#include "runtime.h"
#include <android/log.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "arch/context.h"
#include "art_field-inl.h"
#include "art_method-inl.h"
#include "class_linker-inl.h"
#include "debugger.h"
#include "dex/dex_instruction.h"
#include "entrypoints/runtime_asm_entrypoints.h"
#include "gc/accounting/card_table-inl.h"
#include "interpreter/interpreter.h"
#include "jit/jit.h"
#include "jit/jit_code_cache.h"
#include "jit/profiling_info.h"
#include "jni/jni_internal.h"
#include "mirror/class-inl.h"
#include "mirror/object_array-inl.h"
#include "mirror/object-inl.h"
#include "mirror/string.h"
#include "oat_file-inl.h"
#include "scoped_thread_state_change.h"
#include "well_known_classes.h"
#include "json.h"
#include <fstream>
#include <map>
#include <sstream>
#include <list>
#include "reflection.h"
#include "native/native_util.h"
#include <chrono>
#include "thread.h"
//#include "scoped_fast_native_object_access.h"

using json = nlohmann::json;
using namespace std;

namespace art
{
    extern "C" ArtMethod *jMethodToArtMethod(JNIEnv *env, jobject jMethod);
    map<string, string> methodMap;
    list<const DexFile *> dexFiles;

    bool Xupk::isUnpackFlag = false;
    char Xupk::procName[256] = {};
    Thread *Xupk::xupkThread = nullptr;
    ArtMethod *Xupk::xupkArtMethod = nullptr;

    /**
     * 供 dalvik_system_DexFile.cc->DexFile_fakeInvoke调用
     * 构造主动调用的参数,并进行调用
     */
    void Xupk::xupkFakeInvoke(ArtMethod *artMethod) REQUIRES_SHARED(Locks::mutator_lock_)
    {
        if (artMethod->IsAbstract() || artMethod->IsNative() || (!artMethod->IsInvokable()) || artMethod->IsProxyMethod())
        {
            return;
        }
        JValue result;
        Thread *self = Thread::Current();
        uint32_t args_size = (uint32_t)ArtMethod::NumArgRegisters(artMethod->GetShorty());

        if (!artMethod->IsStatic())
        {
            args_size += 1;
        }
        std::vector<uint32_t> args(args_size, 0);
        if (!artMethod->IsStatic())
        {
            // 第一个参数赋值为除0以外的任何值,因为后面会判断 arg[0]==nullptr
            args[0] = 0x12345678;
        }
        artMethod->Invoke(self, args.data(), args_size, &result, artMethod->GetShorty());
    }

    void Xupk::unpackAppFlag()
    {
        memset(procName, 0, sizeof(procName));
        getProcessName(procName);
        isUnpackFlag = true;
    }

    uint8_t *Xupk::getCodeItemEnd(const uint8_t **pData)
    {
        uint32_t num_of_list = DecodeUnsignedLeb128(pData);
        for (; num_of_list > 0; num_of_list--)
        {
            int32_t num_of_handlers =
                DecodeSignedLeb128(pData);
            int num = num_of_handlers;
            if (num_of_handlers <= 0)
            {
                num = -num_of_handlers;
            }
            for (; num > 0; num--)
            {
                DecodeUnsignedLeb128(pData);
                DecodeUnsignedLeb128(pData);
            }
            if (num_of_handlers <= 0)
            {
                DecodeUnsignedLeb128(pData);
            }
        }
        return (uint8_t *)(*pData);
    }

    /**
     * base64编码
     */
    char *Xupk::base64Encode(char *str, long str_len, long *outlen)
    {
        long len;
        char *res;
        int i, j;
        const char *base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        if (str_len % 3 == 0)
            len = str_len / 3 * 4;
        else
            len = (str_len / 3 + 1) * 4;

        res = (char *)malloc(sizeof(char) * (len + 1));
        res[len] = '\0';
        *outlen = len;
        for (i = 0, j = 0; i < len - 2; j += 3, i += 4)
        {
            res[i] = base64_table[str[j] >> 2];
            res[i + 1] =
                base64_table[(str[j] & 0x3) << 4 |
                             (str[j + 1] >> 4)];
            res[i + 2] =
                base64_table[(str[j + 1] & 0xf) << 2 |
                             (str[j + 2] >> 6)];
            res[i + 3] = base64_table[str[j + 2] & 0x3f];
        }

        switch (str_len % 3)
        {
        case 1:
            res[i - 2] = '=';
            res[i - 1] = '=';
            break;
        case 2:
            res[i - 1] = '=';
            break;
        }

        return res;
    }

    /**
     * 获取当前进程名
     */
    bool Xupk::getProcessName(char *szProcName)
    {
        if(isUnpackFlag)
        {
            memcpy(szProcName, procName, 256);
            return true;
        }
        int fcmdline = -1;
        char szCmdline[64] = {0};
        int procid = getpid();
        sprintf(szCmdline, "/proc/%d/cmdline", procid);
        fcmdline = open(szCmdline, O_RDONLY);
        bool result = true;
        if (fcmdline > 0)
        {
            int len = read(fcmdline, szProcName, 256);
            if (len <= 0)
            {
                LOG(INFO) << "XUPK->art_method.cc:getProcessName,read process name failed:" << strerror(errno);
                result = false;
            }
            for(int i = 0; i < len; i++)
            {
                if(szProcName[i] == ':')
                {
                    szProcName[i] = '\0';
                    break;
                }
            }
        }
        if (!szProcName[0])
        {
            LOG(INFO) << "XUPK->art_method.cc:getProcessName,process name is null:" << strerror(errno);
            result = false;
        }
        close(fcmdline);
        return result;
    }

    /**
     * 将MethodInfo信息从内存映射到文件 
     */
    void Xupk::mapToFile()
    {
        LOG(INFO) << "XUPK->method list file count:" << methodMap.size();
        for (map<string, string>::iterator iter = methodMap.begin(); iter != methodMap.end(); iter++)
        {
            fstream file;
            const char *fileName = iter->first.c_str();
            string methodInfo = iter->second;

            // 删除结尾的逗号,并完善成json格式
            methodInfo.erase(methodInfo.size() - 1);
            methodInfo += "]}";

            // 如果文件已存在,那么删除它
            file.open(fileName, ios::in);
            if (file.is_open())
            {
                remove(fileName);
                LOG(INFO) << "XUPK->remove fileName:" << fileName;
            }
            file.close();

            // 保存到文件
            file.open(fileName, ios::out);
            file << methodInfo;
            file.close();
            LOG(INFO) << "XUPK->dump method information success:" << fileName;
        }
        methodMap.clear();
    }

    /**
     * dump Dex文件里的所有类名
     */
    void Xupk::dumpClassName(const DexFile *dexFile, const char *feature)
    {
        char szProcName[256] = {0};
        if (!getProcessName(szProcName))
        {
            LOG(INFO) << "XUPK->dumpMethod:"
                      << "get process name failed";
            return;
        }
        // 创建目录
        char filePath[256] = {0};
        sprintf(filePath, "/data/data/%s/xupk", szProcName);
        mkdir(filePath, 0777);

        // 构造文件名
        char fileName[256] = {0};
        int dexFileSize = (int)dexFile->Size();
        sprintf(fileName, "%s/%d_%s_class.json", filePath, dexFileSize, feature);

        ifstream iFile;
        iFile.open(fileName, ios::in);
        if (!iFile.is_open())
        {
            // 创建文件
            json root;
            for (size_t i = 0; i < dexFile->NumClassDefs(); i++)
            {
                const dex::ClassDef &classDef = dexFile->GetClassDef(i);
                const char *descriptor = dexFile->GetClassDescriptor(classDef);
                root["count"] = i + 1;
                root["data"][i] = descriptor;
            }
            ofstream oFile;
            oFile.open(fileName, ios::out);
            if (oFile.is_open())
            {
                oFile << root;
                oFile.close();
                LOG(INFO) << "XUPK->dump class name:success:" << fileName;
            }
            else
            {
                //LOG(INFO) << "XUPK->dumpClassName:failed,file name:" << fileName << ",error:" << strerror(errno);
            }
        }
        else
        {
            // 文件已存在
            //LOG(INFO) << "XUPK->dumpClassName:file exist";
            iFile.close();
        }
    }

    /**
     * 获取并储存method的信息
     */
    void Xupk::dumpMethod(ArtMethod *artMethod, const char *feature) REQUIRES_SHARED(Locks::mutator_lock_)
    {
        char *szProcName = (char *)malloc(256);
        memset(szProcName, 0, 256);
        if (!getProcessName(szProcName))
        {
            LOG(INFO) << "XUPK->dumpMethod:"
                      << "get process name failed";
            return;
        }

        const DexFile *dexFile = artMethod->GetDexFile();
        string methodName = artMethod->PrettyMethod(true);
        if (!dexFile->IsStandardDexFile())
        {
            LOG(INFO) << "XUPK->dumpMethod:" << methodName << " is not StandardDexFile";
            return;
        }

        //LOG(INFO) << "XUPK->dumpMethod:"<<methodName;

        const uint8_t *dexFileBegin = dexFile->Begin();

        int dexFileSize = (int)dexFile->Size();
        uint32_t methodIndex = artMethod->GetMethodIndex();
        const StandardDexFile::CodeItem *codeItem = down_cast<const StandardDexFile::CodeItem*>(artMethod->GetCodeItem());
        if (codeItem == nullptr)
        {
            //LOG(ERROR) << "XUPK->dumpMethod:"<< "codeItem is null";
            return;
        }

        // 创建目录
        char *filePath = (char *)malloc(256);
        memset(filePath, 0, 256);
        sprintf(filePath, "/data/data/%s/xupk", szProcName);
        mkdir(filePath, 0777);

        // 构造文件名
        char *fileName = (char *)malloc(256);
        memset(fileName, 0, 256);
        sprintf(fileName, "%s/%d_%s_method.json", filePath, dexFileSize, feature);

        // 计算codeItem的长度
        int codeItemLength = 0;
        uint8_t *item = (uint8_t *)codeItem;
        if (codeItem->tries_size_ > 0)
        {
            const uint8_t *handlerData = (const uint8_t *)(DexFile::GetTryItems(CodeItemDataAccessor(*dexFile, codeItem).end(), codeItem->tries_size_));
            uint8_t *tail = getCodeItemEnd(&handlerData);
            codeItemLength = (int)(tail - item);
        }
        else
        {
            codeItemLength = 16 + codeItem->insns_size_in_code_units_ * 2;
        }

        int offset = (int)(item - dexFileBegin);
        long outlen = 0;
        char *base64Code = base64Encode((char *)item, (long)codeItemLength, &outlen);

        string *methodInfo = nullptr;
        bool isNeedDelete = false;
        if (methodMap.count(fileName))
        {
            // the method list entry exist
            methodInfo = &(methodMap.find(fileName)->second);
        }
        else
        {
            methodInfo = new string();
            isNeedDelete = true;
            (*methodInfo) += "{\"count\":0,\"data\":[";
        }

        // count++
        stringstream sstream;
        int count = 0;
        int pos1 = methodInfo->find("\"count\":");
        int pos2 = methodInfo->find(",\"data\":");
        if (pos1 != -1 && pos2 != -1)
        {
            string strCount = methodInfo->substr(pos1 + 8, pos2 - (pos1 + 8));
            sstream << strCount;
            sstream >> count;
            sstream.clear();
        }
        count++;
        sstream << count;
        string strCount;
        sstream >> strCount;
        sstream.clear();
        methodInfo->replace(pos1 + 8, pos2 - (pos1 + 8), strCount);

        // convert index,offset,codeLen to string
        string strMethodIndex;
        sstream << methodIndex;
        sstream >> strMethodIndex;
        if (strMethodIndex.empty())
            strMethodIndex = "0";
        sstream.clear();

        string strOffset;
        sstream << offset;
        sstream >> strOffset;
        if (strOffset.empty())
            strOffset = "0";
        sstream.clear();

        string strCodeItemLength;
        sstream << codeItemLength;
        sstream >> strCodeItemLength;
        if (strCodeItemLength.empty())
            strCodeItemLength = "0";
        sstream.clear();

        /**
         * add method information to list
         * 不知为何,在这里使用nlohmannjson来操作会发生错误,为了兼容dex修复程序,这里就直接拼接成json格式了
         * @name 函数名
         * @index 函数索引
         * @offset 函数偏移
         * @codeItemLength 函数codeItem长度
         * @inst 函数指令的base64串
         * 修复思路为:获取dex的每一个类里的每一个direct method 和virtual method,并获取其index,和codeOffset
         * 再从下列存储的信息里,找到对应index的method,并将其inst进行base64解码,然后填充回codeOffset
         */
        *methodInfo += "{\"name\":" + string("\"") + methodName + string("\"") + string(",");
        *methodInfo += "\"index\":" + strMethodIndex + string(",");
        *methodInfo += "\"offset\":" + strOffset + string(",");
        *methodInfo += "\"codeItemLength\":" + strCodeItemLength + string(",");
        *methodInfo += "\"inst\":" + string("\"") + string(base64Code) + string("\"");
        *methodInfo += "},";
        methodMap.insert(pair<string, string>(string(fileName), *methodInfo));

        free(szProcName);
        free(filePath);
        free(fileName);
        free(base64Code);
        if (isNeedDelete)
        {
            delete methodInfo;
            methodInfo = nullptr;
        }
    }

    /**
     * dump Dex文件
     */
    void Xupk::dumpDexFile(const DexFile *dexFile, const char *feature) REQUIRES_SHARED(Locks::mutator_lock_)
    {
        char szProcName[256] = {0};
        if (!getProcessName(szProcName))
        {
            LOG(INFO) << "XUPK->dumpDexFile:"
                      << "get process name failed";
            return;
        }

        // make dir in the sdcard for xupk
        const uint8_t *dexFileBegin = dexFile->Begin();
        int dexFileSize = (int)dexFile->Size();

        // 创建目录
        char filePath[256] = {0};
        sprintf(filePath, "/data/data/%s/xupk", szProcName);
        mkdir(filePath, 0777);

        // 构造文件名
        char fileName[256] = {0};
        sprintf(fileName, "%s/%d_%s.dex", filePath, dexFileSize, feature);

        int dexFilefp = open(fileName, O_RDONLY);
        if (dexFilefp > 0)
        {
            // the dex file exist
            close(dexFilefp);
            dexFilefp = 0;
            return;
        }

        // dump the dex file
        dexFilefp = open(fileName, O_CREAT | O_RDWR, 0666);
        if (dexFilefp > 0)
        {
            if (write(dexFilefp, (void *)dexFileBegin, dexFileSize) <= 0)
            {
                LOG(INFO) << "XUPK->dumpDexFile,dex name:" << fileName << ";write dex file failed:" << strerror(errno);
                close(dexFilefp);
                return;
            }
            fsync(dexFilefp);
            close(dexFilefp);
            LOG(INFO) << "XUPK->dump dex file success:" << fileName;
        }
    }

    /**
     * 存储当前线程对象
     * 一般来讲,只有在主动调用线程里会调用这个函数
     */
    void Xupk::setThread(Thread *thread)
    {
        xupkThread = thread;
    }

    /**
     * 存储artMethod
     * 在主动调用时,存储正在调用的method
     */
    void Xupk::setMethod(ArtMethod *method)
    {
        xupkArtMethod = method;
    }

    /**
     * 判断方法是否为主动调用 
     * 根据存储的 xupkThread 和 xupkArtMethod 来判断是否为主动调用的函数
     */
    bool Xupk::isFakeInvoke(Thread *thread, ArtMethod *method) REQUIRES_SHARED(Locks::mutator_lock_)
    {
        if (xupkThread == nullptr || xupkArtMethod == nullptr || thread == nullptr || method == nullptr)
        {
            return false;
        }

        if ((thread->GetTid() == xupkThread->GetTid()) &&
            strcmp(method->PrettyMethod(true).c_str(), xupkArtMethod->PrettyMethod(true).c_str()) == 0)         
        {
            return true;
        }
        return false;
    }

    /**
     * Native函数
     * 将java方法转为ArtMethod对象,并进行主动调用
     */
    static void Xupk_native_fakeInvoke(JNIEnv *env, jclass, jobject jMethod) REQUIRES_SHARED(Locks::mutator_lock_)
    {
        if (env)
        {
        }
        if (jMethod != nullptr)
        {
            Thread *self = Thread::Current();
            ArtMethod *artMethod = jMethodToArtMethod(env, jMethod);
            Xupk::setThread(self);
            Xupk::setMethod(artMethod);
            Xupk::xupkFakeInvoke(artMethod);
        }
        return;
    }

    static void Xupk_mapToFile(JNIEnv *env, jclass)
    {
        if (env)
        {
        }
        Xupk::mapToFile();
    }
    
    static void Xupk_unpackAppFlag(JNIEnv *env, jclass)
    {
        if (env)
        {
        }
        Xupk::unpackAppFlag();
    }


    #ifndef NATIVE_METHOD
    #define NATIVE_METHOD(className, functionName, signature) \
        { #functionName, signature, reinterpret_cast<void*>(className ## _ ## functionName) }
    #endif
    static JNINativeMethod gMethods[] = {
        NATIVE_METHOD(Xupk, native_fakeInvoke, "(Ljava/lang/Object;)V"),
        NATIVE_METHOD(Xupk, mapToFile, "()V"),
        NATIVE_METHOD(Xupk, unpackAppFlag, "()V"),
    };

    // 注册native函数,须在runtime.cc中调用
    void Xupk::register_android_app_Xupk(JNIEnv *env)
    {
        REGISTER_NATIVE_METHODS("android/app/Xupk");
    }

    bool Xupk::isCallChainLog()
    {
        static const char* callChainFileName = "/data/local/tmp/xk_call.config";
        static string callChainProName[2] = {"", ""};
        static int index = 0;
        static uint64_t lastUpdateTimeSec = 0;
        uint64_t nowTimeSec = static_cast<uint64_t>(time(NULL));
        // 默认1秒读取一次
        if (lastUpdateTimeSec + 1 < nowTimeSec)
        {
            lastUpdateTimeSec = nowTimeSec;
            string tmp;
            ifstream in(callChainFileName, ios::in);
            if (!in)
            {
                return false;
            }
            in >> tmp;
            if(tmp.size() > 0 && tmp[tmp.size()-1] == '\n')
            {
                tmp[tmp.size()-1] = '\0';
                tmp.resize(tmp.size()-1);
            }
            callChainProName[!index] = tmp;
            in.close();
            index = !index;
        }
        if(strlen(callChainProName[index]) == 0)
            return false;
        char crr[256];
        memset(crr, 0, sizeof(crr));
        getProcessName(crr);
        return callChainProName[index] == string(crr);
    }
    
    //!unused
    bool Xupk::isDump()
    {
        static const char* callChainFileName = "/data/local/tmp/xk.config";
        static string callChainProName[2] = {"", ""};
        static int index = 0;
        static uint64_t lastUpdateTimeSec = 0;
        uint64_t nowTimeSec = static_cast<uint64_t>(time(NULL));
        // 默认1秒读取一次
        if (lastUpdateTimeSec + 1 < nowTimeSec)
        {
            lastUpdateTimeSec = nowTimeSec;
            string tmp;
            ifstream in(callChainFileName, ios::in);
            if (!in)
            {
                return false;
            }
            in >> tmp;
            if(tmp.size() > 0 && tmp[tmp.size()-1] == '\n')
            {
                tmp[tmp.size()-1] = '\0';
                tmp.resize(tmp.size()-1);
            }
            callChainProName[!index] = tmp;
            in.close();
            index = !index;
        }
        char crr[256];
        memset(crr, 0, sizeof(crr));
        getProcessName(crr);
        return callChainProName[index] == string(crr);
    }

    void Xupk::log(const char* format, ...)
    {
        uint32_t tid = Xupk::gettid();
        char crr[256];
        memset(crr, 0, sizeof(crr));
        getProcessName(crr);
        stringstream ss;
        ss << "/data/data/" << crr << "/callchain_" << getpid() << "_" << tid << ".log";
        FILE* fp = fopen(ss.str().c_str(), "a");
        if(fp != nullptr)
        {
            va_list _va_list;
            va_start(_va_list, format);
            fprintf(fp, "%s tid[%d] ", log_time().c_str(), tid);
            vfprintf(fp, format, _va_list);
            fprintf(fp, "\n");
            va_end(_va_list);
            fflush(fp);
            fclose(fp);
        }
    }
    
    string Xupk::log_time()
    {
        auto tt = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        struct tm* ptm = localtime(&tt);
        char date[60] = { 0 };
        sprintf(date, "%d-%02d-%02d-%02d.%02d.%02d",
            (int)ptm->tm_year + 1900, (int)ptm->tm_mon + 1, (int)ptm->tm_mday,
            (int)ptm->tm_hour, (int)ptm->tm_min, (int)ptm->tm_sec);
        return string(date);
    }
}
