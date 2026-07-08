import Dependencies._

scalaVersion := "3.8.4"
version := "0.1.0-SNAPSHOT"
scalacOptions ++= Seq(
  "-no-indent",
  "-deprecation",
  "-feature",
  "-unchecked",
  "-explain", // + actionable error messages
  "-source:3.3", // + pin source level, no silent drift
  // "-Wunused:all",
  "-Wvalue-discard",
  "-Wnonunit-statement",
  "-Wsafe-init",
  "-language:strictEquality", // + catch nonsensical == (Money vs String, etc.)
  "-Xkind-projector",
  "-Xmax-inlines",
  "64"
)

lazy val root = (project in file("."))
  .settings(
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
// Required while src/main/java holds sources in this module: Scala pipelining's
// early-output (sig) JARs don't carry Java-compiled classes downstream, so
// Test/compile fails with bogus "not found" errors. Disable until the Java
// sources move to their own subproject.
// defaults to true in sbt 2.0.0
ThisBuild / usePipelining := false

ThisBuild / outputStrategy := Some(StdoutOutput)
