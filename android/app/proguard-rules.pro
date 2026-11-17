# 本应用所有类都在这个包内，保留类名 / 方法签名，避免 R8 误删入口与反射调用。
-keep class com.example.nfctaplink.** { *; }
-dontwarn org.json.**
-dontwarn android.**
