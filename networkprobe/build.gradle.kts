plugins {
    id("com.android.application")
}

android {
    namespace = "com.apexscribe.networkprobe"
    compileSdk = rootProject.extra["appCompiledSdk"] as Int
    defaultConfig {
        applicationId = "com.apexscribe.networkprobe"
        minSdk = 29
        targetSdk = rootProject.extra["appTargetSdk"] as Int
        versionCode = 1
        versionName = "1"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}
