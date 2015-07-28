#include <jni.h>
#include <string.h>
#include <assert.h>
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef LOG_TAG
#define LOG_TAG "cc"
#define LOGE(...)__android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)
#endif

static char* gpackageName;
static char* gDexpath;
typedef struct DexFileMap {
    void *optdex;
    void *injectData;
    void *string_idx;
    void *type_idx;
    void *field_idx;
    void *method_idx;
    void *proto_idx;
    void *class_def;
    void *dexfile;
}DexFileMap;

typedef struct _funcInfo{
  Elf32_Addr st_value;
  Elf32_Word st_size;
}funcInfo;

struct DexFileMap *gDexmap;
void init() __attribute__((constructor));

unsigned elfhash(const char *_name)
{
    const unsigned char *name = (const unsigned char *) _name;
    unsigned h = 0, g;

    while(*name) {
        h = (h << 4) + *name++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
    return h;
}

int getDexPath(char* dexpath, unsigned long *addr){
    int pid = getpid();
    char fileName[20];
    FILE* file;
    char *begin, *end;
    int length, i;
    if (!pid)
        return 1;
    sprintf(fileName, "/proc/%d/maps", pid);
    LOGE("fileName : %s", fileName);
    file = fopen(fileName, "r");
    if (file) {
        char line[256];
        while (1) {
            memset(line, 0, 256);
            if (!fgets(line, 256, file))
                return 1;
            if (strstr(line, gpackageName) && strstr(line, "/data/dalvik-cache")){
                if ((begin = strstr(line, "/data@app@")) != NULL ||
                    (begin = strstr(line, "/mnt@asec@")) != NULL){
                        end = strstr(line, "@classes.dex");
                        length = end - begin;
                        *addr = strtoul(line, 0, 16);
                        if (end)
                            break;
                    }
            }
        }
        strncpy(dexpath, begin, length);
        for (i = 0; i < length; i++)
            if (dexpath[i] == '@')
                dexpath[i] = '/';
        LOGE("dexpath is : %s", dexpath);
        fclose(file);
        return 0;
    }
    return 1;
}
int getDexfileHeader(struct DexFileMap *map, void *dex){
    (*map).dexfile = dex;
    (*map).string_idx = dex + *(int *)(dex + 60);
    (*map).type_idx = dex + *(int *)(dex + 68);
    (*map).proto_idx = dex + *(int *)(dex + 76);
    (*map).field_idx = dex + *(int *)(dex + 84);
    (*map).method_idx = dex + *(int *)(dex + 92);
    (*map).class_def = dex + *(int *)(dex + 100);
    (*map).injectData = dex + *(int *)(dex + 104) + *(int *)(dex + 108);
    return 0;
}
int getDexMap(struct DexFileMap *map, int addr){
    void *optdexfile;
    optdexfile = addr;
    if (!memcmp(optdexfile, "dey\n", 4u) &&
        !memcmp(optdexfile + 4, "036", 4u)){
        (*map).optdex = optdexfile;
        LOGE("find the odex , dexoffset is %d, dexlength is %d:",
            *(unsigned int*)(optdexfile + 8),
            *(unsigned int*)(optdexfile + 12));
    }else{
        LOGE("bad opt version (0x%02x %02x %02x %02x)",
            *(char *)(optdexfile),
            *(char *)(optdexfile+1),
            *(char *)(optdexfile+2),
            *(char *)(optdexfile+3));
         return 1;
    }
    getDexfileHeader(map, optdexfile + *(int *)(optdexfile + 8));
    return 0;
}

int getStringName(struct DexFileMap *map, int string_idx){
    int i, result;
    i = (*map).dexfile + *(unsigned int *)((*map).string_idx + 4 * string_idx);
    for (; ; i++){
        result = i + 1;
        if (*(unsigned char *)i <= 0x7f)
            break;
    }
    return result;
}

int getTypeName(struct DexFileMap *map, int type_idx){
    return getStringName(map, *(int *)((*map).type_idx + 4 * type_idx));
}

int fixmethod(JNIEnv *env, jobject obj, unsigned long addr){
    void *dex;
    int class_type_idx, method_idx, access_flags, code_off, i;
    short proto_idx;
    char *class_name, *className, *method_name, proto_str[256], *tmp_type;
    void *proto;
    unsigned int parameter_off, list_size, index = 0;
    jclass cls;
    jmethodID meth;

    if (!gDexmap){
        gDexmap = malloc(sizeof(DexFileMap));
        memset(gDexmap, 0, sizeof(DexFileMap));
        int len = sizeof(DexFileMap);
        if (!gDexmap)
            return 1;
        if (getDexMap(gDexmap, addr)){
            LOGE("get dex map failed");
            return 1;
        }
    }
    dex = (*gDexmap).dexfile;
    class_type_idx = *(int *)((*gDexmap).injectData);
    method_idx = *(int *)((*gDexmap).injectData + 4);
    access_flags = *(int *)((*gDexmap).injectData + 8);
    code_off = *(int *)((*gDexmap).injectData + 12);
//    class_type_idx = 1615;
//    method_idx = 13839;
//    access_flags = 4;
//    code_off = 795352;

    class_name = (char *)getTypeName(gDexmap, class_type_idx);
    method_name = (char *)getStringName(gDexmap, *(int *)((*gDexmap).method_idx + 8 * method_idx + 4));
    proto_idx = *(short *)((*gDexmap).method_idx + 8 * method_idx + 2);
    proto = (*gDexmap).proto_idx + 12 * proto_idx;
    parameter_off = *(unsigned int *)(proto + 8);
    strncpy(proto_str + index, "(", 1);
    index += 1;
    if (parameter_off){
        list_size = *(unsigned int *)(dex + parameter_off);
        for (i = 0; i < list_size; i++){
            tmp_type = getTypeName(gDexmap, *(unsigned short *)(dex + parameter_off + 4 + 2 * i));
            strncpy(proto_str + index, tmp_type, strlen(tmp_type));
            index += strlen(tmp_type);
        }
    }
    strncpy(proto_str + index, ")", 1);
    index += 1;
    tmp_type = getTypeName(gDexmap, *(unsigned int *)(proto + 4));
    strncpy(proto_str + index, tmp_type, strlen(tmp_type));
    index += strlen(tmp_type);
    proto_str[index] = '\0';
    className = malloc(strlen(class_name)-1);
    if (className) {
        strcpy(className, class_name + 1);  // delete 'L' at the beginning
        className[strlen(class_name)-2] = '\0';
        LOGE("class name : %s", className);
        LOGE("method name : %s", method_name);
        LOGE("code off : %x", code_off);
        LOGE("proto string : %s", proto_str);
    }else {
        LOGE("malloc className failed");
        return 1;
    }
    cls = (*env)->FindClass(env, className);
    if (cls) {
        meth = (*env)->GetMethodID(env, cls, method_name, proto_str);
        if (meth) {
            LOGE("get method access_flag is : %x", *(unsigned int *)((int)meth + 4));
            LOGE("register size : %d, insSize : %d, outSize : %d, triesSize: %d, insnsSize : %d",
                *(unsigned short *)(dex + code_off),
                *(unsigned short *)(dex + code_off + 2),
                *(unsigned short *)(dex + code_off + 4),
                *(unsigned short *)(dex + code_off + 6),
                *(unsigned int *)(dex + code_off + 12)
                );
            *(unsigned int *)((int)meth + 4) = access_flags;
            *(unsigned short *)((int)meth + 10) = *(unsigned short *)(dex + code_off); //register size
            *(unsigned short *)((int)meth + 12) = *(unsigned short *)(dex + code_off + 4); //out size
            *(unsigned short *)((int)meth + 14) = *(unsigned short *)(dex + code_off + 2); //in size
            *(unsigned int *)((int)meth + 32) = dex + code_off + 16; //insns
            *(unsigned int *)((int)meth + 40) = 0;    //nativeFunc = NULL
        }else{
            LOGE("get method %s failed", method_name);
        }
    }else {
        LOGE("get class %s failed", className);
    }
    return 0;
}

jint native_hello(JNIEnv *env, jobject obj, jstring package){
  char* str = (*env)->GetStringUTFChars(env, package, JNI_FALSE);
  unsigned long addr;
  __android_log_print(ANDROID_LOG_ERROR, "cc", "the str is: %s", str);
  if (!gpackageName)
    gpackageName = str;
  if (!gDexpath){
    gDexpath = malloc(0x64u);
    if (!gDexpath)
        return 1;
    memset(gDexpath, 0, 0x64u);
    if (getDexPath(gDexpath, &addr)) {
        LOGE("get dex path error");
        return 1;
    }
    LOGE("get addr :%x", addr);
//    if (fixmethod(env, obj, addr)){
//        LOGE("fix method error");
//        return 1;
//    }
  }
  return 0;
}

static JNINativeMethod gMethods[] = {
  {"getStringFromNative", "(Ljava/lang/String;)I", (void*)native_hello},
};


/*
* 为某一个类注册本地方法
*/
static int registerNativeMethods(JNIEnv* env
        , const char* className
        , JNINativeMethod* gMethods, int numMethods) {
    jclass clazz;
    clazz = (*env)->FindClass(env, className);
    if (clazz == NULL) {
        return JNI_FALSE;
    }
    if ((*env)->RegisterNatives(env, clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }

    return JNI_TRUE;
}


/*
* 为所有类注册本地方法
*/
static int registerNatives(JNIEnv* env) {
    const char* kClassName = "com/cc/test/ProxyShell";//指定要注册的类
    return registerNativeMethods(env, kClassName, gMethods,
            sizeof(gMethods) / sizeof(gMethods[0]));
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved){
    JNIEnv* env = NULL;
    jint result = -1;

    if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_4) != JNI_OK) {
        return -1;
    }
    assert(env != NULL);

    if (!registerNatives(env)) {//注册
        return -1;
    }
    //成功
    result = JNI_VERSION_1_4;

    return result;
}

void getFunc(unsigned long base, const char *funcname, funcInfo *info){
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdr;
    Elf32_Off dyn_vaddr;
    Elf32_Word dyn_size, dyn_strsz;
    Elf32_Dyn *dyn;
    Elf32_Addr dyn_symtab, dyn_strtab, dyn_hash;
    Elf32_Sym *funSym;
    unsigned *bucket, *chain;
    char *dynstr;
    unsigned funHash, nbucket;
    int i;
    char flag = 0;

    ehdr = (Elf32_Ehdr *)base;
    phdr = (Elf32_Phdr *)(base + ehdr->e_phoff);
    for (i = 0; i < ehdr->e_phnum; i++){
        if(phdr->p_type == PT_DYNAMIC){
            flag = 1;
            break;
        }
        phdr++;
    }
    if(!flag)
        goto _error;
    dyn_vaddr = phdr->p_vaddr + base;
    dyn_size = phdr->p_filesz;
    flag = 0;
    dyn = (Elf32_Dyn *)dyn_vaddr;
    for (i = 0; i < dyn_size / sizeof(Elf32_Dyn); i++){
        if (dyn->d_tag == DT_SYMTAB) {
            dyn_symtab = (dyn->d_un).d_ptr;
            flag += 1;
            LOGE("Find .dynsym section, addr = 0x%x\n", dyn_symtab);
        }
        if (dyn->d_tag == DT_HASH){
            dyn_hash = (dyn->d_un).d_ptr;
            flag += 2;
            LOGE("Find .hash section, addr = 0x%x\n", dyn_hash);
        }
        if (dyn->d_tag == DT_STRTAB){
            dyn_strtab = (dyn->d_un).d_ptr;
            flag += 4;
            LOGE("Find .dynstr section, addr = 0x%x\n", dyn_strtab);
        }
        if (dyn->d_tag == DT_STRSZ){
            dyn_strsz = (dyn->d_un).d_val;
            flag += 8;
            LOGE("Find strsz size = 0x%x\n", dyn_strsz);
        }
        dyn++;
    }
    if ((flag & 0xf) != 0xf){
        LOGE("Find needed .section failed\n");
        goto _error;
    }
    dyn_symtab += base;
    dyn_hash += base;
    dyn_strtab += base;

    funHash = elfhash(funcname);
    funSym = (Elf32_Sym *)dyn_symtab;
    dynstr = (char *)dyn_strtab;
    nbucket = *(int *)dyn_hash;
    bucket = (unsigned *)(dyn_hash + 8);
    chain = (unsigned *)(dyn_hash + 8 + 4 * nbucket);
    flag = 0;
    for (i = bucket[funHash % nbucket]; i != 0; i = chain[i]){
        if(!strcmp(dynstr + (funSym + i)->st_name, funcname)){
            LOGE("Find %s\n", funcname);
            flag = 1;
            break;
        }
    }
    if (!flag)
        goto _error;
    info->st_value = (funSym + i)->st_value;
    info->st_size = (funSym + i)->st_size;
_error:
    return;
}

unsigned int getLibAddr(char *libname){
    int pid;
    unsigned int ret = 0;
    char buf[1024];
    FILE *fd;
    pid = getpid();
    sprintf(buf, "/proc/%d/maps", pid);
    LOGE("Start to init %s", buf);
    fd = fopen(buf, "r");
    if (fd == NULL) {
        LOGE("open failed");
        goto _error;
    }
    while(fgets(buf, sizeof(buf), fd)){
        if(strstr(buf, libname)){
            LOGE("the line is %s", buf);
            ret = strtoul(buf, 0, 16);
            break;
        }
    }
_error:
    fclose(fd);
    return ret;
}

void init() {
    const char func[] = "native_hello";
    unsigned int base, npage;
    int i;
    funcInfo info;
    base = getLibAddr("libtest.so");
    LOGE("get base addr %d", base);
    getFunc(base, func, &info);
    LOGE("get func info %d, %d", info.st_size, info.st_value);
    npage = info.st_size / PAGE_SIZE + ((info.st_size % PAGE_SIZE == 0) ? 0 : 1);
    npage = info.st_size / PAGE_SIZE + ((info.st_size % PAGE_SIZE == 0) ? 0 : 1);
    if(mprotect((void *) ((base + info.st_value) / PAGE_SIZE * PAGE_SIZE), npage, PROT_READ | PROT_EXEC | PROT_WRITE) != 0){
        LOGE("mem privilege change failed");
    }

    for(i=0;i< info.st_size - 1; i++){
    	char *addr = (char*)(base + info.st_value -1 + i);
    	*addr = ~(*addr);
    }

    if(mprotect((void *) ((base + info.st_value) / PAGE_SIZE * PAGE_SIZE), npage, PROT_READ | PROT_EXEC) != 0){
    	LOGE("mem privilege change failed");
    }
    LOGE("Done");
}