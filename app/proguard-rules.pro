# R8 rules for VulFT release builds.
# Room, WorkManager, Compose, Navigation3 and kotlinx.serialization ship their own consumer rules.

# --- JavaMail (com.sun.mail:android-mail / android-activation)
# Providers, data handlers and MIME types are loaded by class name from META-INF resources.
-keep class com.sun.mail.** { *; }
-keep class javax.mail.** { *; }
-keep class javax.activation.** { *; }
-keep class com.sun.activation.** { *; }
-keep class myjava.awt.datatransfer.** { *; }
-dontwarn java.awt.**
-dontwarn java.beans.**
-dontwarn javax.security.**
-dontwarn javax.naming.**
-dontwarn org.apache.harmony.**
-dontwarn com.sun.mail.**
-dontwarn javax.activation.**

# --- kotlinx.serialization: keep serializers of our @Serializable classes (settings, fix info, ranges).
-keepclassmembers @kotlinx.serialization.Serializable class com.vulft.app.** {
    *** Companion;
    kotlinx.serialization.KSerializer serializer(...);
}
-keepclasseswithmembers class com.vulft.app.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# --- Navigation3 keys are @Serializable objects/classes used to restore the back stack.
-keep class com.vulft.app.*Route { *; }
-keep class com.vulft.app.*Route$* { *; }

# --- WorkManager instantiates the worker by class name.
-keep class com.vulft.app.SyncWorker { <init>(...); }

# Readable stack traces in crash logs.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
