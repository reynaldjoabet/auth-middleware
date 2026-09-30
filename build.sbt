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
  .dependsOn(core % "compile->compile;test->test")
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
      skunkCore,
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
      "-J-XX:+ExitOnOutOfMemoryError",
      // cats-effect records every fiber step to enrich stack traces; profiled
      // at ~15% of CPU on the request path. Re-enable for debugging with
      // JAVA_OPTS=-Dcats.effect.tracing.mode=cached.
      "-Dcats.effect.tracing.mode=none"
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

// JMH microbenchmarks for the authentication hot path. Not part of the
// service; run with e.g. `bench/Jmh/run -i 5 -wi 3 -f 1 -t 1`.
lazy val bench = (project in file("bench"))
  .dependsOn(root)
  .enablePlugins(JmhPlugin)
  .settings(
    name := "auth-middleware-bench",
    // Its own JVM, so a benchmark's CPU and GC figures are its alone, not the
    // sbt server's.
    Compile / run / fork := true,
    // Only for bench.BareNetty, the backend comparison: the service runs on Ember.
    libraryDependencies ++= http4sNettyServer +: nettyNativeTransports,
    scalaVersion         := "3.9.0",
    publish / skip       := true
  )

// Framework-independent auth core, shared by the http4s service (root) and the
// ZIO service (zio): refined types, token verification, credential parsing,
// challenge rendering and request ids. No HTTP library, effect system, config
// or logging library: each service brings its own. The two services depend on core and never on each other, so each can use the
// same class names (auth.AccessTokenAuth, auth.AuthEvents, …) for its own
// implementation without clashing on a classpath.
lazy val core = (project in file("core"))
  .settings(
    name                 := "auth-core",
    scalaVersion         := "3.9.0",
    libraryDependencies ++= Seq(
      // Framework-neutral: token verification, credential parsing, the
      // challenge model. No HTTP server, effect system, config or logging.
      iron,
      nimbusJoseJwt,
      nimbusOauth2Oidc,
      Dependencies.caffeine,
      munit
    ),
    publish / skip := true
  )

// The same Bearer-token middleware on ZIO + zio-http, to compare runtimes (see
// README "http4s vs ZIO"). Built on core only: it differs from the http4s
// service just in effect system, HTTP server and Redis client.
lazy val zio = (project in file("zio"))
  .dependsOn(core % "compile->compile;test->test")
  .enablePlugins(JavaAppPackaging)
  .settings(
    name                 := "auth-middleware-zio",
    libraryDependencies ++= Seq(
      Dependencies.zio,
      Dependencies.zioHttp,
      Dependencies.sageClientZio,
      Dependencies.zioConfig,
      Dependencies.zioConfigTypesafe,
      scribe,
      // Routes Netty's and the Redis client's slf4j logging into scribe.
      scribeSlf4j2,
      munit
    ),
    scalaVersion             := "3.9.0",
    Compile / mainClass      := Some("auth.Main"),
    Universal / javaOptions ++= Seq(
      "-J-XX:MaxRAMPercentage=75",
      "-J-XX:+ExitOnOutOfMemoryError"
    ),
    publish / skip := true
  )
