import java.util.Properties

plugins {
  alias(libs.plugins.android.application)
  alias(libs.plugins.ksp)
  alias(libs.plugins.compose.compiler)
  alias(libs.plugins.kotlin.serialization)
}

// Release signing comes from keystore.properties (git-ignored). Without it, release builds are unsigned.
val signingProps = Properties().apply {
  val f = rootProject.file("keystore.properties")
  if (f.exists()) f.inputStream().use { load(it) }
}

// App version (see scheme in defaultConfig).
val appMajor = 1
val appMinor = 1
val appPatch = 8
require(appMajor in 1..99 && appMinor in 1..9 && appPatch in 1..9) { "Version out of range: major 1-99, minor 1-9, patch 1-9" }

android {
  namespace = "com.vulft.app"
  compileSdk = 37
  defaultConfig {
    applicationId = "com.vulft.app"
    minSdk = 26
    targetSdk = 37
    // Version scheme: major 1–99, minor 1–9, patch 1–9.
    // Bump patch each release; after patch 9 → minor+1, patch 1; after minor 9 → major+1, minor 1.
    versionCode = appMajor * 100 + appMinor * 10 + appPatch
    versionName = "$appMajor.$appMinor.$appPatch"
  }

  signingConfigs {
    if (signingProps.getProperty("storeFile") != null) {
      create("release") {
        storeFile = rootProject.file(signingProps.getProperty("storeFile"))
        storePassword = signingProps.getProperty("storePassword")
        keyAlias = signingProps.getProperty("keyAlias")
        keyPassword = signingProps.getProperty("keyPassword")
      }
    }
  }

  buildTypes {
    release {
      signingConfig = signingConfigs.findByName("release")
      isMinifyEnabled = false
      proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
    }
  }
  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
  }
  buildFeatures {
    compose = true
    aidl = false
    buildConfig = false
    shaders = false
  }

  packaging {
    resources {
      excludes += setOf("/META-INF/{AL2.0,LGPL2.1}", "META-INF/NOTICE.md", "META-INF/LICENSE.md")
    }
  }
}

kotlin {
  jvmToolchain(17)
}

dependencies {
  val composeBom = platform(libs.androidx.compose.bom)
  implementation(composeBom)
  androidTestImplementation(composeBom)

  // Core Android dependencies
  implementation(libs.androidx.core.ktx)
  implementation(libs.androidx.lifecycle.runtime.ktx)
  implementation(libs.androidx.activity.compose)

  // Arch Components
  implementation(libs.androidx.lifecycle.runtime.compose)
  implementation(libs.androidx.lifecycle.viewmodel.compose)

  // Compose
  implementation(libs.androidx.compose.ui)
  implementation(libs.androidx.compose.ui.tooling.preview)
  implementation(libs.androidx.compose.material3)
  // Tooling
  debugImplementation(libs.androidx.compose.ui.tooling)
  // Instrumented tests
  androidTestImplementation(libs.androidx.compose.ui.test.junit4)
  debugImplementation(libs.androidx.compose.ui.test.manifest)

  // Local tests: jUnit, coroutines, Android runner
  testImplementation(libs.junit)
  testImplementation(libs.kotlinx.coroutines.test)

  // Instrumented tests: jUnit rules and runners
  androidTestImplementation(libs.androidx.test.core)
  androidTestImplementation(libs.androidx.test.ext.junit)
  androidTestImplementation(libs.androidx.test.runner)
  androidTestImplementation(libs.androidx.test.espresso.core)

  // Data, background sync, email
  implementation(libs.androidx.room.runtime)
  implementation(libs.androidx.room.ktx)
  ksp(libs.androidx.room.compiler)
  implementation(libs.androidx.work.runtime.ktx)
  implementation(libs.kotlinx.serialization.json)
  implementation(libs.javamail.android)
  implementation(libs.javamail.activation)
  implementation(libs.androidx.compose.material.icons.core)
  implementation(libs.androidx.compose.material.icons.extended)

  // Navigation
  implementation(libs.androidx.navigation3.ui)
  implementation(libs.androidx.navigation3.runtime)
  implementation(libs.androidx.lifecycle.viewmodel.navigation3)
}
