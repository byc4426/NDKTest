#include <jni.h>
#include <string>

const char *APP_PACKAGE_NAME = "com.guangdong.xxx";
// 验证是否通过
static jboolean auth = JNI_FALSE;

/*
 * 获取全局 Application
 */
jobject getApplicationContext(JNIEnv *env) {
    jclass activityThread = env->FindClass("android/app/ActivityThread");
    jmethodID currentActivityThread = env->GetStaticMethodID(activityThread,
                                                             "currentActivityThread",
                                                             "()Landroid/app/ActivityThread;");
    jobject at = env->CallStaticObjectMethod(activityThread, currentActivityThread);
    jmethodID getApplication = env->GetMethodID(activityThread, "getApplication",
                                                "()Landroid/app/Application;");
    return env->CallObjectMethod(at, getApplication);
}


extern "C"
JNIEXPORT jboolean JNICALL
Java_com_yuedao_winery_ndk_JniUtil_init(JNIEnv *env, jclass clazz) {
    jclass binderClass = env->FindClass("android/os/Binder");
    jclass contextClass = env->FindClass("android/content/Context");
    jclass signatureClass = env->FindClass("android/content/pm/Signature");
    jclass packageNameClass = env->FindClass("android/content/pm/PackageManager");
    jclass packageInfoClass = env->FindClass("android/content/pm/PackageInfo");

    jmethodID packageManager = env->GetMethodID(contextClass, "getPackageManager",
                                                "()Landroid/content/pm/PackageManager;");
    jmethodID packageName = env->GetMethodID(contextClass, "getPackageName",
                                             "()Ljava/lang/String;");
    jmethodID toCharsString = env->GetMethodID(signatureClass, "toCharsString",
                                               "()Ljava/lang/String;");
    jmethodID packageInfo = env->GetMethodID(packageNameClass, "getPackageInfo",
                                             "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jmethodID nameForUid = env->GetMethodID(packageNameClass, "getNameForUid",
                                            "(I)Ljava/lang/String;");
    jmethodID callingUid = env->GetStaticMethodID(binderClass, "getCallingUid", "()I");

    jint uid = env->CallStaticIntMethod(binderClass, callingUid);

    // 获取全局 Application
    jobject context = getApplicationContext(env);

    jobject packageManagerObject = env->CallObjectMethod(context, packageManager);
    jstring packNameString = (jstring) env->CallObjectMethod(context, packageName);
    jobject packageInfoObject = env->CallObjectMethod(packageManagerObject, packageInfo,packNameString, 64);
    jfieldID signaturefieldID = env->GetFieldID(packageInfoClass, "signatures","[Landroid/content/pm/Signature;");
    jobjectArray signatureArray = (jobjectArray) env->GetObjectField(packageInfoObject,signaturefieldID);
    jobject signatureObject = env->GetObjectArrayElement(signatureArray, 0);
    jstring runningPackageName = (jstring) env->CallObjectMethod(packageManagerObject, nameForUid,uid);

    if (runningPackageName) {// 正在运行应用的包名
        const char *charPackageName = env->GetStringUTFChars(runningPackageName, JNI_FALSE);
//        LOGE("runningPackageName %s", charPackageName);
        if (strcmp(charPackageName, APP_PACKAGE_NAME) != 0) {
            return JNI_FALSE;
        }
        env->ReleaseStringUTFChars(runningPackageName, charPackageName);
    } else {
        return JNI_FALSE;
    }

    jstring signatureStr = (jstring) env->CallObjectMethod(signatureObject, toCharsString);
    const char *signature = env->GetStringUTFChars(
            (jstring) env->CallObjectMethod(signatureObject, toCharsString), NULL);

    env->DeleteLocalRef(binderClass);
    env->DeleteLocalRef(contextClass);
    env->DeleteLocalRef(signatureClass);
    env->DeleteLocalRef(packageNameClass);
    env->DeleteLocalRef(packageInfoClass);

//    LOGE("current apk signature %s", signature);

// 应用签名，通过 JNIDecryptKey.getSignature(getApplicationContext())
// 获取，注意开发版和发布版的区别，发布版需要使用正式签名打包后获取
    const char *SIGNATURE_KEY = "30820276308201dfa00302010202040a2525c3300d06092a845686f70d01010b0500306e310b300906035504061302383631123010060355040813096775616e67646f6e6731123010060355040713096775616e677a686f75310d300b060355040a130467646169310d300b060355040b13046764616931193017060355040313104170705369676e61747572652e6a6b73301e170d3233303533303130333033325a170d3433303532353130333033325a306e310b300906035504061302383631123010060355040813096775616e67646f6e6731123010060355040713096775616e677a686f75310d300b060355040a130467646169310d300b060355040b13046764616931193017060355040313104170705369676e61747572652e6a6b7330819f300d06092a864886f70d010101050003818d0030818902818100e164112ee3f215a43f158221623c1000e2c91f64f208526811d5edd9a32f9c7fb0a50648a88177c441ab0106d037d09cc4834b8ef484794cc7a5fdbbfa48a16fd6c668e93bbfdcf918b5e1d705e0b1be282f898301882a2698e648bc4d3c7a710dd9c868709645416db6ab86ad632288da34ce542f3ea0ba4e1ce85e8f9e45ab0203010001a321301f301d0603551d0e04160414beead1f845076f6c4fa2c56b64d9e07d862f83dd300d06092a864886f70d01010b050003818100766117be69f7a8cf750bb44e32226b2bd453a56f9f3e52823e12a17faa735ab0ac1c1d07caf2fd921cb81fb1d6bc631e16d70148d0a75324f3db50cfd23d31794e7cc236330aaee541db41be265b8ea2eecbfa67cd468735797b946c9dd3955de6f1522a477c78fd20ec14fba21b9801a9a0b6cc5c0bb7948572cc0284544359";
    if (strcmp(signature, SIGNATURE_KEY) == 0) {
//        LOGE("verification passed");
        env->ReleaseStringUTFChars(signatureStr, signature);
        auth = JNI_TRUE;
        return JNI_TRUE;
    } else {
//        LOGE("verification failed");
        auth = JNI_FALSE;
        return JNI_FALSE;
    }
    return auth;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_yuedao_winery_ndk_JniUtil_getKey(JNIEnv *env, jclass clazz) {
    char *a = "a";
    char *b = "b";
    char *c = "c";
    char *d = "d";
    char *e = "e";
    char *f = "f";
    char *g = "g";
    char *h = "h";
    char *i = "i";
    char *j = "j";
    char *k = "k";
    char *l = "l";
    char *m = "m";
    char *n = "n";
    char *o = "o";
    char *p = "p";
    char *q = "q";
    char *r = "r";
    char *s = "s";
    char *t = "t";
    char *u = "u";
    char *v = "v";
    char *w = "w";
    char *x = "x";
    char *y = "y";
    char *z = "z";
    char *i1 = "1";
    char *i2 = "2";
    char *i3 = "3";
    char *i4 = "4";
    char *i5 = "5";
    char *i6 = "6";
    char *i7 = "7";
    char *i8 = "8";
    char *i9 = "9";
    char *i0 = "0";

    //    const char *DECRYPT_KEY = "cedpxfl6tfwbx3w0ke5uup1i3xjyeu4v";
    char ack[33] = "";
    strcat(ack, c);
    strcat(ack, e);
    strcat(ack, d);
    strcat(ack, p);
    strcat(ack, x);
    strcat(ack, f);
    strcat(ack, l);
    strcat(ack, i6);
    strcat(ack, t);
    strcat(ack, f);
    strcat(ack, w);
    strcat(ack, b);
    strcat(ack, x);
    strcat(ack, i3);
    strcat(ack, w);
    strcat(ack, i0);
    strcat(ack, k);
    strcat(ack, e);
    strcat(ack, i5);
    strcat(ack, u);
    strcat(ack, u);
    strcat(ack, p);
    strcat(ack, i1);
    strcat(ack, i);
    strcat(ack, i3);
    strcat(ack, x);
    strcat(ack, j);
    strcat(ack, y);
    strcat(ack, e);
    strcat(ack, u);
    strcat(ack, i4);
    strcat(ack, v);
    if (auth) {
        return env->NewStringUTF(ack);
    } else {// 你没有权限，验证没有通过。
        return env->NewStringUTF("You don't have permission, the verification didn't pass.");
    }
}
