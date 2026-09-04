#include "property_compat.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

constexpr size_t kMaxProperties = 512;
constexpr size_t kMaxKeyLength = 127;
// ro.build.version.known_codenames is longer than the historical Android
// PROP_VALUE_MAX on the Samsung framework used by this experiment.
constexpr size_t kMaxValueLength = 1023;

struct PropertyEntry {
    bool used;
    char key[kMaxKeyLength + 1];
    char value[kMaxValueLength + 1];
};

PropertyEntry properties[kMaxProperties]{};
size_t property_count = 0;
bool properties_loaded = false;

void trim(char *text) {
    if (!text) return;

    char *begin = text;
    while (*begin == ' ' || *begin == '\t' || *begin == '\r' || *begin == '\n') {
        ++begin;
    }
    if (begin != text) {
        std::memmove(text, begin, std::strlen(begin) + 1);
    }

    size_t length = std::strlen(text);
    while (length > 0) {
        char last = text[length - 1];
        if (last != ' ' && last != '\t' && last != '\r' && last != '\n') break;
        text[--length] = '\0';
    }
}

PropertyEntry *find_property(const char *key) {
    if (!key) return nullptr;
    for (size_t i = 0; i < property_count; ++i) {
        if (properties[i].used && std::strcmp(properties[i].key, key) == 0) {
            return &properties[i];
        }
    }
    return nullptr;
}

bool set_property(const char *key, const char *value) {
    if (!key || !*key || !value) return false;
    if (std::strlen(key) > kMaxKeyLength || std::strlen(value) > kMaxValueLength) {
        return false;
    }

    PropertyEntry *entry = find_property(key);
    if (!entry) {
        if (property_count >= kMaxProperties) return false;
        entry = &properties[property_count++];
        entry->used = true;
        std::strncpy(entry->key, key, kMaxKeyLength);
        entry->key[kMaxKeyLength] = '\0';
    }
    std::strncpy(entry->value, value, kMaxValueLength);
    entry->value[kMaxValueLength] = '\0';
    return true;
}

void load_property_file(const char *path) {
    if (!path || !*path) return;
    FILE *file = std::fopen(path, "r");
    if (!file) return;

    char line[2048];
    while (std::fgets(line, sizeof(line), file)) {
        trim(line);
        if (!line[0] || line[0] == '#' || line[0] == ';') continue;

        char *separator = std::strchr(line, '=');
        if (!separator) continue;
        *separator = '\0';
        char *key = line;
        char *value = separator + 1;
        trim(key);
        trim(value);
        if (key[0]) set_property(key, value);
    }
    std::fclose(file);
}

void load_properties_once() {
    if (properties_loaded) return;
    properties_loaded = true;

    const char *explicit_file = std::getenv("ATLAS_PROPERTY_FILE");
    if (explicit_file && *explicit_file) {
        load_property_file(explicit_file);
    } else {
        // These are the usual standalone Android property-file locations.
        // Later files override earlier values, matching the normal build
        // property overlay convention for the keys used by Build.VERSION.
        load_property_file("/system/build.prop");
        load_property_file("/system/etc/prop.default");
        load_property_file("/product/build.prop");
        load_property_file("/vendor/build.prop");
        load_property_file("/odm/etc/build.prop");
    }

    // The standalone host has no init/property service, so the ABI keys that
    // Android normally derives during boot may be absent from build.prop.
    // These values describe the actual AArch64 execution environment and are
    // only installed when the real property is unavailable.
    if (!find_property("ro.product.cpu.abilist64")) {
        set_property("ro.product.cpu.abilist64", "arm64-v8a");
    }
    if (!find_property("ro.product.cpu.abilist32")) {
        set_property("ro.product.cpu.abilist32", "armeabi-v7a,armeabi");
    }
    if (!find_property("ro.product.cpu.abilist")) {
        set_property("ro.product.cpu.abilist", "arm64-v8a,armeabi-v7a,armeabi");
    }
    // Build.VERSION indexes all_codenames[0]. Release builds use REL; without
    // the property service this key may otherwise become an empty array.
    if (!find_property("ro.build.version.all_codenames")) {
        set_property("ro.build.version.all_codenames", "REL");
    }

    std::fprintf(stderr,
                 "[property-compat] loaded %zu properties (file=%s)\n",
                 property_count,
                 explicit_file && *explicit_file ? explicit_file : "default search");
    if (!find_property("ro.build.version.sdk")) {
        std::fprintf(stderr,
                     "[property-compat] WARNING: ro.build.version.sdk is unavailable; "
                     "Build.VERSION will use its Java default\n");
    }
}

bool get_key(JNIEnv *env, jstring key_string, char *key, size_t key_size) {
    if (!key_string || !key || key_size == 0) return false;
    const char *utf_key = env->GetStringUTFChars(key_string, nullptr);
    if (!utf_key) return false;
    std::strncpy(key, utf_key, key_size - 1);
    key[key_size - 1] = '\0';
    env->ReleaseStringUTFChars(key_string, utf_key);
    return true;
}

jstring make_string(JNIEnv *env, const char *value) {
    return env->NewStringUTF(value ? value : "");
}

const char *get_value(const char *key) {
    PropertyEntry *entry = find_property(key);
    return entry ? entry->value : nullptr;
}

const char *get_value_or_default(const char *key, const char *default_value) {
    const char *value = get_value(key);
    return value ? value : (default_value ? default_value : "");
}

PropertyEntry *entry_from_handle(jlong handle) {
    if (handle == 0) return nullptr;
    for (size_t i = 0; i < property_count; ++i) {
        if (handle == reinterpret_cast<jlong>(&properties[i])) {
            return &properties[i];
        }
    }
    return nullptr;
}

bool parse_boolean(const char *value, bool *result) {
    if (!value || !result) return false;
    if (std::strcmp(value, "1") == 0 || std::strcmp(value, "true") == 0 ||
        std::strcmp(value, "TRUE") == 0 || std::strcmp(value, "y") == 0 ||
        std::strcmp(value, "yes") == 0 || std::strcmp(value, "on") == 0) {
        *result = true;
        return true;
    }
    if (std::strcmp(value, "0") == 0 || std::strcmp(value, "false") == 0 ||
        std::strcmp(value, "FALSE") == 0 || std::strcmp(value, "n") == 0 ||
        std::strcmp(value, "no") == 0 || std::strcmp(value, "off") == 0) {
        *result = false;
        return true;
    }
    return false;
}

jlong parse_long(const char *value, jlong default_value) {
    if (!value || !*value) return default_value;
    errno = 0;
    char *end = nullptr;
    long long parsed = std::strtoll(value, &end, 0);
    if (errno != 0 || end == value || (end && *end != '\0')) return default_value;
    return static_cast<jlong>(parsed);
}

jstring native_get(JNIEnv *env, jclass, jstring key_string) {
    char key[kMaxKeyLength + 1]{};
    if (!get_key(env, key_string, key, sizeof(key))) return make_string(env, "");
    return make_string(env, get_value_or_default(key, ""));
}

jstring native_get_with_default(JNIEnv *env, jclass, jstring key_string,
                                jstring default_string) {
    char key[kMaxKeyLength + 1]{};
    if (!get_key(env, key_string, key, sizeof(key))) return make_string(env, "");

    const char *default_value = "";
    if (default_string) {
        const char *utf_default = env->GetStringUTFChars(default_string, nullptr);
        if (utf_default) {
            jstring result = make_string(env, get_value_or_default(key, utf_default));
            env->ReleaseStringUTFChars(default_string, utf_default);
            return result;
        }
    }
    return make_string(env, get_value_or_default(key, default_value));
}

jint native_get_int(JNIEnv *env, jclass, jstring key_string, jint default_value) {
    char key[kMaxKeyLength + 1]{};
    if (!get_key(env, key_string, key, sizeof(key))) return default_value;
    return static_cast<jint>(parse_long(get_value(key), default_value));
}

jlong native_get_long(JNIEnv *env, jclass, jstring key_string, jlong default_value) {
    char key[kMaxKeyLength + 1]{};
    if (!get_key(env, key_string, key, sizeof(key))) return default_value;
    return parse_long(get_value(key), default_value);
}

jboolean native_get_boolean(JNIEnv *env, jclass, jstring key_string,
                            jboolean default_value) {
    char key[kMaxKeyLength + 1]{};
    if (!get_key(env, key_string, key, sizeof(key))) return default_value;
    bool parsed = false;
    return parse_boolean(get_value(key), &parsed) ? (parsed ? JNI_TRUE : JNI_FALSE)
                                                   : default_value;
}

jlong native_find(JNIEnv *env, jclass, jstring key_string) {
    char key[kMaxKeyLength + 1]{};
    if (!get_key(env, key_string, key, sizeof(key))) return 0;
    PropertyEntry *entry = find_property(key);
    return entry ? reinterpret_cast<jlong>(entry) : 0;
}

jstring native_get_handle(JNIEnv *env, jclass, jlong handle) {
    PropertyEntry *entry = entry_from_handle(handle);
    return make_string(env, entry ? entry->value : "");
}

jint native_get_int_handle(JNIEnv *, jclass, jlong handle, jint default_value) {
    PropertyEntry *entry = entry_from_handle(handle);
    return static_cast<jint>(parse_long(entry ? entry->value : nullptr, default_value));
}

jlong native_get_long_handle(JNIEnv *, jclass, jlong handle, jlong default_value) {
    PropertyEntry *entry = entry_from_handle(handle);
    return parse_long(entry ? entry->value : nullptr, default_value);
}

jboolean native_get_boolean_handle(JNIEnv *, jclass, jlong handle,
                                   jboolean default_value) {
    PropertyEntry *entry = entry_from_handle(handle);
    bool parsed = false;
    return parse_boolean(entry ? entry->value : nullptr, &parsed)
               ? (parsed ? JNI_TRUE : JNI_FALSE)
               : default_value;
}

void native_set(JNIEnv *env, jclass, jstring key_string, jstring value_string) {
    char key[kMaxKeyLength + 1]{};
    if (!get_key(env, key_string, key, sizeof(key)) || !value_string) return;
    const char *value = env->GetStringUTFChars(value_string, nullptr);
    if (!value) return;
    set_property(key, value);
    env->ReleaseStringUTFChars(value_string, value);
}

void native_noop(JNIEnv *, jclass) {}

const JNINativeMethod kMethods[] = {
    {"native_add_change_callback", "()V", reinterpret_cast<void *>(native_noop)},
    {"native_find", "(Ljava/lang/String;)J", reinterpret_cast<void *>(native_find)},
    {"native_get", "(J)Ljava/lang/String;", reinterpret_cast<void *>(native_get_handle)},
    {"native_get", "(Ljava/lang/String;)Ljava/lang/String;", reinterpret_cast<void *>(native_get)},
    {"native_get", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
     reinterpret_cast<void *>(native_get_with_default)},
    {"native_get_boolean", "(JZ)Z", reinterpret_cast<void *>(native_get_boolean_handle)},
    {"native_get_boolean", "(Ljava/lang/String;Z)Z",
     reinterpret_cast<void *>(native_get_boolean)},
    {"native_get_int", "(JI)I", reinterpret_cast<void *>(native_get_int_handle)},
    {"native_get_int", "(Ljava/lang/String;I)I", reinterpret_cast<void *>(native_get_int)},
    {"native_get_long", "(JJ)J", reinterpret_cast<void *>(native_get_long_handle)},
    {"native_get_long", "(Ljava/lang/String;J)J", reinterpret_cast<void *>(native_get_long)},
    {"native_report_sysprop_change", "()V", reinterpret_cast<void *>(native_noop)},
    {"native_set", "(Ljava/lang/String;Ljava/lang/String;)V", reinterpret_cast<void *>(native_set)},
};

}  // namespace

bool install_system_properties_compat(JNIEnv *env) {
    const char *enabled = std::getenv("ATLAS_SYSTEM_PROPERTIES_COMPAT");
    if (enabled && (std::strcmp(enabled, "0") == 0 || std::strcmp(enabled, "false") == 0)) {
        std::fprintf(stderr, "[property-compat] disabled by ATLAS_SYSTEM_PROPERTIES_COMPAT\n");
        return true;
    }

    load_properties_once();

    if (std::getenv("ATLAS_PROPERTY_TRACE")) {
        const char *trace_keys[] = {
            "ro.build.version.sdk",
            "ro.build.version.all_codenames",
            "ro.build.version.known_codenames",
            "ro.product.cpu.abilist64",
            "ro.product.cpu.abilist32",
            "ro.product.first_api_level",
            "ro.build.fingerprint",
        };
        for (const char *key : trace_keys) {
            PropertyEntry *entry = find_property(key);
            const char *value = entry ? entry->value : nullptr;
            std::fprintf(stderr, "[property-compat] %s=%s\n", key,
                         value ? value : "<missing>");
        }
    }

    jclass system_properties = env->FindClass("android/os/SystemProperties");
    if (!system_properties || env->ExceptionCheck()) {
        std::fprintf(stderr, "[property-compat] android.os.SystemProperties not found\n");
        env->ExceptionDescribe();
        env->ExceptionClear();
        return false;
    }

    // RegisterNatives itself does not execute SystemProperties.<clinit>.
    // Register one overload at a time: framework releases do not all expose
    // the same native overloads, and one missing method would otherwise make
    // an all-at-once RegisterNatives call fail atomically.
    jint active_count = 0;
    for (const JNINativeMethod &candidate : kMethods) {
        jint status = env->RegisterNatives(
            system_properties, const_cast<JNINativeMethod *>(&candidate), 1);
        if (status == JNI_OK && !env->ExceptionCheck()) {
            ++active_count;
            continue;
        }
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (active_count == 0) {
        std::fprintf(stderr, "[property-compat] no SystemProperties natives installed\n");
        env->DeleteLocalRef(system_properties);
        return false;
    }

    env->DeleteLocalRef(system_properties);
    std::fprintf(stderr, "[property-compat] SystemProperties natives installed (%d methods)\n",
                 active_count);
    return true;
}
