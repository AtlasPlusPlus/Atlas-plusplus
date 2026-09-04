#include "main.hpp"
#include <cstdio>
#include <dlfcn.h>
#include <jni.h>

extern "C" struct JniInvocationImpl *JniInvocationCreate();
extern "C" bool JniInvocationInit(struct JniInvocationImpl *instance,
                                  const char *library_name);
extern "C" jint registerFrameworkNatives(JNIEnv *env);
extern "C" jint JNI_OnLoad(JavaVM *vm, void *reserved);

extern void fuzz_one_input();

JavaVM *vm{nullptr};
JNIEnv *env{nullptr};
pid_t pid{};

struct JniInvocationImpl {
    const char *jni_provider_library_name;
    void *jni_provider_library;
    jint (*JNI_GetDefaultJavaVMInitArgs)(void *);
    jint (*JNI_CreateJavaVM)(JavaVM **, JNIEnv **, void *);
    jint (*JNI_GetCreatedJavaVMs)(JavaVM **, jsize, jsize *);
};

int init_jvm(JavaVM **p_vm, JNIEnv **p_env, JavaVMInitArgs *args) {
    printf("[+] Starting initialization\n");

    struct JniInvocationImpl *invoc = JniInvocationCreate();
    printf("[+] JniInvocationCreate finished\n");
    JniInvocationInit(invoc, "libart.so");
    printf("[+] JniInvocationInit finished\n");
    jint status = 0;
    status = JNI_CreateJavaVM(p_vm, p_env, args);
    printf("[+] JNI_CreateJavaVM finished\n");

    if (status != JNI_OK) {
        printf("[!] Can't create java vm/env \nstatus = %d \n", status);
        return JNI_ERR;
    }

    printf("[+] Initialization completed successfully.\n"
           "[+] Java VM pointer: %p\n"
           "[+] Java env pointer: %p\n",
           *p_vm, *p_env);

    status = 0;
    status = registerFrameworkNatives(*p_env);
    if (status != JNI_OK) {
        printf("[!] Can't registerFrameworkNatives\nstatus =%d \n", status);
        return JNI_ERR;
    }

    // Build.VERSION is initialized lazily when an application class first
    // touches the Android framework.  Standalone ART does not have the
    // Android property service, so install a deterministic, harness-local
    // SystemProperties backend before any target class is looked up.
    if (!install_system_properties_compat(*p_env)) {
        printf("[!] Can't install SystemProperties compatibility layer\n");
        return JNI_ERR;
    }

    return 0;
}

int main() {
    JavaVMInitArgs args{};
    args.version = JNI_VERSION_1_6;
    args.nOptions = 1;
    JavaVMOption options[args.nOptions];
    args.options = options;
    char optionString[0x100]{};
    strcat(optionString, "-Djava.class.path=");
    strcat(optionString, APK_PATH);
    options[0].optionString = optionString;

    int init_jvm_status{init_jvm(&vm, &env, &args)};
    if (init_jvm_status != 0) {
        return init_jvm_status;
    }
    printf("[+] successfully init jvm!\n");

    auto handle{dlopen(LIB_PATH, RTLD_LAZY)};
    if (!handle) {
        printf("[+] dlopen failed: %s\n", dlerror());
        return 1;
    }
    auto JNI_OnLoad_addr{dlsym(handle, "JNI_OnLoad")};
    if (JNI_OnLoad_addr) {
        reinterpret_cast<decltype(&JNI_OnLoad)>(JNI_OnLoad_addr)(vm, nullptr);
        printf("[+] JNI_OnLoad finished!\n");
    }

    pid = getpid();
    fuzz_one_input();
    dlclose(handle);
    return 0;
}
