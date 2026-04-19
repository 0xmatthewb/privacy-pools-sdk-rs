plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.oxbow.reactnative.privacypoolssdk"
    compileSdk = 35

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    sourceSets.getByName("main") {
        manifest.srcFile("src/main/AndroidManifest.xml")
        java.srcDirs(
            "src/main/java",
            "src/main/kotlin",
            "generated/src/main/java",
        )
        jniLibs.srcDir("src/main/jniLibs")
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
    implementation("com.facebook.react:react-android")
    implementation("net.java.dev.jna:jna:5.14.0@aar")
}
