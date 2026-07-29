import Dependencies._

scalaVersion := "3.8.4"
version := "0.1.0-SNAPSHOT"

ThisBuild / scalacOptions := Seq(
  "-no-indent",
  "-deprecation",
  "-feature",
  "-unchecked",
  "-source:3.3",
  "-language:strictEquality",
  "-java-output-version:21",
  "-Werror",
  "-Wunused:all",
  "-Wvalue-discard",
  "-Wnonunit-statement",
  "-Wshadow:all",
  "-Wsafe-init",
  "-Xcheck-macros",
  "-Xmax-inlines:64"
)

Global / onChangedBuildSource := ReloadOnSourceChanges

lazy val root = (project in file("."))
  .settings(
    semanticdbEnabled := true,
    name := "auth-middleware",
    // Use ++= so PlayJava plugin defaults (play/play-java/jackson) remain on the classpath.
    libraryDependencies ++= Seq(
      iron,
      munit,
      catsEffect,
      http4sDsl,
      emberServer,
      emberClient,
      http4sCirce,
      jsoniter,
      jsoniterMacros,
      circeCore,
      circeGeneric,
      ironJsoniter,
      fs2,
      fs2Kafka,
      vault,
      slf4j,
      nimbusJoseJwt,
      nimbusOauth2Oidc,
      munitCatsEffect,
      munit,
      ironPureconfig,
      pureconfig,
      pureconfigGeneric,
      Dependencies.caffeine,
      Dependencies.hikaricp,
      Dependencies.flyway,
      Dependencies.flywayPostgres % Runtime,
      Dependencies.postgres % Runtime,
      Dependencies.logback % Runtime,
      otelJava,
      "io.opentelemetry" % "opentelemetry-exporter-otlp" % "1.63.0" % Runtime,
      "io.opentelemetry" % "opentelemetry-sdk-extension-autoconfigure" % "1.63.0" % Runtime,
      Dependencies.sageClientCe,
      Dependencies.sageClientZio,
      guice,
      "jakarta.inject" % "jakarta.inject-api" % "2.0.1",
      "com.outr" %% "scribe" % "3.19.0",
      "com.outr" %% "scribe-slf4j" % "3.19.0"
    )
  )
  .enablePlugins(PlayJava)
  .disablePlugins(PlayLayoutPlugin)

javaOptions += "-Dotel.java.global-autoconfigure.enabled=true"

addCommandAlias("fmt", "scalafmtAll; scalafmtSbt")
addCommandAlias("fmtCheck", "scalafmtCheckAll; scalafmtSbtCheck")

Test / parallelExecution := true

ThisBuild / outputStrategy := Some(StdoutOutput)
