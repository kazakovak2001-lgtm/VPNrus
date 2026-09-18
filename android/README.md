# Android build environment

Build this project with a JDK 21 distribution. Set `JAVA_HOME` to that JDK before invoking the wrapper, then verify the environment with:

```text
gradlew.bat --version
```

The Gradle JVM in that output must be Java 21. The Android sources and Kotlin bytecode continue to target Java 17 as declared in `app/build.gradle.kts`; that target level is independent of the JDK used to run Gradle.

Validated commands:

```text
gradlew.bat :app:testDebugUnitTest
gradlew.bat :app:assembleDebug
```

The repository pins Gradle 8.10, Android Gradle Plugin 8.7.3, and Kotlin 1.9.24. The current stack was observed to fail when Gradle runs on Java 26, so Java 21 is the supported build environment until a separately reviewed toolchain upgrade is completed.
