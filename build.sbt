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
  "-java-output-version:21",
  "-Werror",
  "-Wunused:all",
  "-Wvalue-discard",
  "-Wnonunit-statement",
  "-language:strictEquality",
  "-Xcheck-macros",
  "-Xmax-inlines:64",
  "-Wsafe-init"
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
    ),
    // -- Packaging (`Docker/publishLocal`, `Universal/packageBin`) -----------
    // PlayJava would package Play's ProdServerStart; the service is the http4s
    // stack. MultiNodeMain is the load-balanced production posture.
    Compile / mainClass := Some("app.MultiNodeMain"),
    // No Scaladoc in the package: it slows every build and ships nothing.
    Compile / doc / sources  := Seq.empty,
    Universal / javaOptions ++= Seq(
      // Without this the packaged app's OpenTelemetry is a silent no-op.
      "-Dotel.java.global-autoconfigure.enabled=true",
      // Size the heap from the container limit, and die on OOM so the
      // orchestrator restarts the node instead of it limping on.
      "-J-XX:MaxRAMPercentage=75",
      "-J-XX:+ExitOnOutOfMemoryError"
    ),
    dockerBaseImage    := "eclipse-temurin:21-jre",
    dockerExposedPorts := Seq(8080),
    // Defaults the deployment can override. Record 1% of new traces (and
    // follow the caller's decision when it sent one): full tracing at high
    // request rates costs more than the service itself.
    dockerEnvVars := Map(
      "OTEL_SERVICE_NAME"       -> "auth-middleware",
      "OTEL_TRACES_SAMPLER"     -> "parentbased_traceidratio",
      "OTEL_TRACES_SAMPLER_ARG" -> "0.01"
    )
  )
  .enablePlugins(PlayJava, DockerPlugin)
  .disablePlugins(PlayLayoutPlugin)

javaOptions += "-Dotel.java.global-autoconfigure.enabled=true"

addCommandAlias("fmt", "scalafmtAll; scalafmtSbt")
addCommandAlias("fmtCheck", "scalafmtCheckAll; scalafmtSbtCheck")

Test / parallelExecution := true

ThisBuild / outputStrategy := Some(StdoutOutput)
