-keep public class * extends com.github.ichurkin.apkvalidator.ApkValidator
-keepclassmembers class * extends com.github.ichurkin.apkvalidator.ApkValidator {
   public *** ***(***);
   public *** ***();
}
-keepclassmembers class * extends java.lang.Enum {
    <fields>;
    public static **[] values();
    public static ** valueOf(java.lang.String);
}
-keepclassmembers public class com.android.apksig.** {
    public *;
}