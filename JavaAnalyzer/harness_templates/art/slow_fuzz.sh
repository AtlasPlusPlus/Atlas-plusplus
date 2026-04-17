#!/bin/bash
rm -rf out/
mkdir in &> /dev/null
dd if=/dev/urandom of=in/sample.bin bs=16 count=16 &> /dev/null
[ -e "main" ] || exit 1

export HOME=/
export ANDROID_DATA=/data
export ANDROID_TZDATA_ROOT=/apex/com.android.tzdata
export ANDROID_ART_ROOT=/apex/com.android.art
export ANDROID_ROOT=/system
export ANDROID_I18N_ROOT=/apex/com.android.i18n

export SYSTEMSERVERCLASSPATH=/system/framework/com.android.location.provider.jar:/system/framework/knoxanalyticssdk.jar:/system/framework/services.jar:/system/framework/ssrm.jar:/system/framework/semwifi-service.jar:/apex/com.android.adservices/javalib/service-adservices.jar:/apex/com.android.adservices/javalib/service-sdksandbox.jar:/apex/com.android.appsearch/javalib/service-appsearch.jar:/apex/com.android.art/javalib/service-art.jar:/apex/com.android.media/javalib/service-media-s.jar:/apex/com.android.permission/javalib/service-permission.jar:/apex/com.samsung.android.ipm/javalib/service-samsung-ipm.jar:/apex/com.samsung.android.shell/javalib/service-samsung-privilege.jar
export STANDALONE_SYSTEMSERVER_JARS=/apex/com.android.btservices/javalib/service-bluetooth.jar:/apex/com.android.os.statsd/javalib/service-statsd.jar:/apex/com.android.scheduling/javalib/service-scheduling.jar:/apex/com.android.tethering/javalib/service-connectivity.jar:/apex/com.android.uwb/javalib/service-uwb.jar:/apex/com.android.wifi/javalib/service-wifi.jar
export DEX2OATBOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar:/apex/com.android.art/javalib/core-libart.jar:/apex/com.android.art/javalib/okhttp.jar:/apex/com.android.art/javalib/bouncycastle.jar:/apex/com.android.art/javalib/apache-xml.jar:/system/framework/framework.jar:/system/framework/framework-graphics.jar:/system/framework/ext.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/knoxsdk.jar:/system/framework/SmpsManager.jar:/system/framework/uibc_java.jar:/system/framework/esecomm.jar:/apex/com.android.i18n/javalib/core-icu4j.jar
export BOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar:/apex/com.android.art/javalib/core-libart.jar:/apex/com.android.art/javalib/okhttp.jar:/apex/com.android.art/javalib/bouncycastle.jar:/apex/com.android.art/javalib/apache-xml.jar:/system/framework/framework.jar:/system/framework/framework-graphics.jar:/system/framework/ext.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/knoxsdk.jar:/system/framework/SmpsManager.jar:/system/framework/uibc_java.jar:/system/framework/esecomm.jar:/apex/com.android.i18n/javalib/core-icu4j.jar:/apex/com.android.adservices/javalib/framework-adservices.jar:/apex/com.android.adservices/javalib/framework-sdksandbox.jar:/apex/com.android.appsearch/javalib/framework-appsearch.jar:/apex/com.android.btservices/javalib/framework-bluetooth.jar:/apex/com.android.conscrypt/javalib/conscrypt.jar:/apex/com.android.ipsec/javalib/android.net.ipsec.ike.jar:/apex/com.android.media/javalib/updatable-media.jar:/apex/com.android.mediaprovider/javalib/framework-mediaprovider.jar:/apex/com.android.ondevicepersonalization/javalib/framework-ondevicepersonalization.jar:/apex/com.android.os.statsd/javalib/framework-statsd.jar:/apex/com.android.permission/javalib/framework-permission.jar:/apex/com.android.permission/javalib/framework-permission-s.jar:/apex/com.android.scheduling/javalib/framework-scheduling.jar:/apex/com.android.sdkext/javalib/framework-sdkextensions.jar:/apex/com.android.tethering/javalib/framework-connectivity.jar:/apex/com.android.tethering/javalib/framework-connectivity-t.jar:/apex/com.android.tethering/javalib/framework-tethering.jar:/apex/com.android.uwb/javalib/framework-uwb.jar:/apex/com.android.wifi/javalib/framework-wifi.jar:/apex/com.samsung.android.ipm/javalib/framework-samsung-ipm.jar:/apex/com.samsung.android.shell/javalib/framework-samsung-privilege.jar

export LD_LIBRARY_PATH=
export AFL_QEMU_INST_RANGES=
export AFL_QEMU_FORCE_DFL=1
export AFL_USE_QASAN=1

afl-fuzz -Q -c main -i in -o out -t 5000 -- ./main