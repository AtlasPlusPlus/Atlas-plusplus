#pragma once

#include <jni.h>

// Install a harness-local implementation of android.os.SystemProperties.
// The implementation is deliberately read-only from the point of view of the
// target API: it reads a deterministic build.prop-style file and supplies the
// same default-value semantics as the Java SystemProperties helpers.
bool install_system_properties_compat(JNIEnv *env);
