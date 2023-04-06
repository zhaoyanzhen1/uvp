plugins {
    id("org.springframework.boot")
    id("io.spring.dependency-management")
    id("java")
    id("war")
}

repositories {
    mavenCentral()
}

val packageUrlJavaVersion: String by project
val annotationVersion: String by project
val log4jdbcVersion: String by project
val springdocVersion: String by project

dependencies {
    implementation(project(":model"))
    implementation(project(":interface"))
    implementation(project(":dao"))
    implementation(project(":quartz"))
    implementation(project(":utility"))
    implementation(project(":clients"))
    implementation(project(":cache"))
    implementation(project(":batch"))

    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.retry:spring-retry")
    implementation("com.github.package-url:packageurl-java:$packageUrlJavaVersion")
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:$springdocVersion")

    runtimeOnly("org.springframework.boot:spring-boot-starter-aop")

    providedRuntime("org.springframework.boot:spring-boot-starter-tomcat")

    testImplementation("org.bgee.log4jdbc-log4j2:log4jdbc-log4j2-jdbc4.1:$log4jdbcVersion")
}

springBoot {
    mainClass.set("org.opensourceway.uvp.UvpApplication")
}

allprojects {
    apply(plugin = "org.springframework.boot")
    apply(plugin = "io.spring.dependency-management")
    apply(plugin = "java")

    repositories {
        mavenCentral()
    }

    dependencies {
        implementation("org.apache.logging.log4j:log4j-api")
        implementation("org.apache.logging.log4j:log4j-core")
        implementation("org.apache.logging.log4j:log4j-slf4j2-impl")
        implementation("org.slf4j:slf4j-api")
        implementation("org.jetbrains:annotations:$annotationVersion")

        testImplementation("org.springframework.boot:spring-boot-starter-test")
    }

    configurations {
        all {
            exclude(group = "org.springframework.boot", module = "spring-boot-starter-logging")
        }
    }
}

subprojects {
    group = rootProject.group
    version = rootProject.version
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}