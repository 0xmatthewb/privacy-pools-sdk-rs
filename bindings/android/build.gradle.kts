plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.oxbow.privacypoolssdk"
    compileSdk = 35

    defaultConfig {
        minSdk = 24
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    sourceSets.getByName("main") {
        manifest.srcFile("src/main/AndroidManifest.xml")
        java.srcDirs("src/main/kotlin", "generated/src/main/java")
        jniLibs.srcDir("src/main/jniLibs")
    }

    sourceSets.getByName("androidTest") {
        assets.srcDir("../../fixtures")
        System.getenv("PRIVACY_POOLS_ANDROID_TEST_ASSETS_DIR")
            ?.takeIf { it.isNotBlank() }
            ?.let { assets.srcDir(it) }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    api("net.java.dev.jna:jna:5.14.0@aar")
    androidTestImplementation("net.java.dev.jna:jna:5.14.0@aar")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
