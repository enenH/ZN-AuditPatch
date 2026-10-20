import com.android.build.gradle.AppExtension

plugins {
    alias(libs.plugins.agp.app) apply false
}

// also the soname
val moduleId by extra("auditpatch")
val moduleName by extra("ZN - Audit Patch")
val verName by extra("v1.2.0")
// Preserve the recovered release identity without rewriting Git history.
// Pass -PreleaseVersionCode=... and -PreleaseCommitHash=... for subsequent builds.
val verCode by extra(providers.gradleProperty("releaseVersionCode").orElse("18").get().toInt())
val commitHash by extra(providers.gradleProperty("releaseCommitHash").orElse("4d8d26d").get())
val abiList by extra(listOf("arm64-v8a", "x86_64"))

val androidMinSdkVersion by extra(26)
val androidTargetSdkVersion by extra(35)
val androidCompileSdkVersion by extra(35)
val androidBuildToolsVersion by extra("35.0.0")
val androidCompileNdkVersion by extra("27.1.12297006")
val androidSourceCompatibility by extra(JavaVersion.VERSION_21)
val androidTargetCompatibility by extra(JavaVersion.VERSION_21)

tasks.register("Delete", Delete::class) {
    delete(rootProject.buildDir)
}

fun Project.configureBaseExtension() {
    extensions.findByType(AppExtension::class)?.run {
        namespace = "io.github.aviraxp.auditpatch"
        compileSdkVersion(androidCompileSdkVersion)
        ndkVersion = androidCompileNdkVersion
        buildToolsVersion = androidBuildToolsVersion

        defaultConfig {
            minSdk = androidMinSdkVersion
        }

        compileOptions {
            sourceCompatibility = androidSourceCompatibility
            targetCompatibility = androidTargetCompatibility
        }
    }

}

subprojects {
    plugins.withId("com.android.application") {
        configureBaseExtension()
    }
    plugins.withType(JavaPlugin::class.java) {
        extensions.configure(JavaPluginExtension::class.java) {
            sourceCompatibility = androidSourceCompatibility
            targetCompatibility = androidTargetCompatibility
        }
    }
}
