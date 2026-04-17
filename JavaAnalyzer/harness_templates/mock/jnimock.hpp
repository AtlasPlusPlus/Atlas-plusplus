#pragma once
#include <jni.h>

namespace jnimock {
extern JNIEnv *env;

// Initialized JNI_VERSION. Usually you needn't use it.
// In case that target native methods accept specific `GetVersion()` values,
// you'll have to assign it to specific value manually or fill this var with
// fuzz input.
extern jint version;

void garbage_collect();
} // namespace jnimock