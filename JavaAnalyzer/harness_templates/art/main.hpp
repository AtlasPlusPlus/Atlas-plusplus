#pragma once
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <jni.h>
#include <unistd.h>

#include "property_compat.hpp"

extern JNIEnv *env;
extern const char APK_PATH[];
extern const char LIB_PATH[];
extern pid_t pid;
