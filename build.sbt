import Dependencies._

scalaVersion := "3.9.0"
version      := "0.1.0-SNAPSHOT"

ThisBuild / scalacOptions := Seq(
  "-encoding",
  "UTF-8",
  "-no-indent",
  "-deprecation",
  "-feature",
  "-unchecked",
  // "-Werror",
  "-java-output-version:21",
  "-Wvalue-discard",
  "-language:strictEquality",
  // "-Wnonunit-statement",
  "-Xcheck-macros",
  "-Xmax-inlines:64",
  "-Yfuture-lazy-vals",
  "-Ysafe-init"
)

Global / onChangedBuildSource := ReloadOnSourceChanges

lazy val root = (project in file("."))
  .settings(
    semanticdbEnabled    := true,
    name                 := "auth-middleware",
    scalacOptions        := scalacOptions.value.distinct,
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
      Dependencies.postgres       % Runtime,
      Dependencies.logback        % Runtime,
      otelJava,
      "io.opentelemetry" % "opentelemetry-exporter-otlp"               % "1.66.0" % Runtime,
      "io.opentelemetry" % "opentelemetry-sdk-extension-autoconfigure" % "1.66.0" % Runtime,
      Dependencies.sageClientCe,
      Dependencies.sageClientZio,
      guice,
      "jakarta.inject" % "jakarta.inject-api" % "2.0.1",
      scribe,
      scribeSlf4j2
    ),
    excludeDependencies ++= Seq(
      ExclusionRule("ch.qos.logback", "logback-classic"),
      ExclusionRule("ch.qos.logback", "logback-core"),
      ExclusionRule("org.playframework", "play-logback_3")
    )
  )
  .enablePlugins(PlayJava)
  .disablePlugins(PlayLayoutPlugin)

javaOptions += "-Dotel.java.global-autoconfigure.enabled=true"

addCommandAlias("fmt", "scalafmtAll; scalafmtSbt")
addCommandAlias("fmtCheck", "scalafmtCheckAll; scalafmtSbtCheck")

Test / parallelExecution := true

ThisBuild / outputStrategy := Some(StdoutOutput)
