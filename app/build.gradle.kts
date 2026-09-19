plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.example.filecorruptor"
    compileSdk = 34
    // Pinned so a local build (Android Studio) and CI always compile the
    // native memory helper (see app/src/main/cpp) against the identical NDK
    // — otherwise which NDK gets auto-detected can silently drift between
    // machines, the same class of problem this repo already pins Gradle's
    // own version to avoid.
    ndkVersion = "26.1.10909125"

    defaultConfig {
        applicationId = "com.example.filecorruptor"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        ndk {
            // The native memory helper only ever runs on a real device via
            // `su`, so there's no need to build it for the emulator's x86
            // ABIs — arm is what every real Android phone/tablet uses.
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    // AGP has defaulted to keeping native .so files compressed inside the
    // APK's zip (loaded via direct mmap) rather than extracted to a real
    // file on disk since AGP 4.2. That's fine for an actual shared library
    // loaded through System.loadLibrary(), but librtmemhelper.so is really
    // a standalone executable we invoke by path via `su -c` — with the
    // default packaging it likely never exists as a runnable file at
    // nativeLibraryDir at all, which silently breaks every helper call,
    // not just process listing. This forces the old "always extract to
    // disk at install time" behavior back on.
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.2")
    implementation("androidx.activity:activity-compose:1.9.0")

    implementation(platform("androidx.compose:compose-bom:2024.09.03"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.animation:animation")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.navigation:navigation-compose:2.7.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.2")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.2")
    implementation("androidx.documentfile:documentfile:1.0.1")

    debugImplementation("androidx.compose.ui:ui-tooling")
}
