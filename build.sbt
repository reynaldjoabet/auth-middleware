import Dependencies._

ThisBuild / scalaVersion := "3.3.8"
ThisBuild / version := "0.1.0-SNAPSHOT"
ThisBuild / scalacOptions ++= Seq(
  "-encoding",
  "UTF-8",
  "-no-indent",
  "-deprecation",
  "-feature",
  "-unchecked",
  "-explain", // + actionable error messages
  "-source:3.3", // + pin source level, no silent drift
  // "-Wunused:all",
  "-Wvalue-discard",
  "-Wnonunit-statement",
  "-Ysafe-init",
  "-language:strictEquality", // + catch nonsensical == (Money vs String, etc.)
  "-Ykind-projector",
  "-Xmax-inlines",
  "64"
)

lazy val root = (project in file("."))
  .settings(
    name := "auth-middleware",
    libraryDependencies := Seq(
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
      caffeine,
      otelJava,
      "io.opentelemetry" % "opentelemetry-exporter-otlp" % "1.63.0" % Runtime,
      "io.opentelemetry" % "opentelemetry-sdk-extension-autoconfigure" % "1.63.0" % Runtime
    )
  )

javaOptions += "-Dotel.java.global-autoconfigure.enabled=true"

addCommandAlias("fmt", "scalafmtAll; scalafmtSbt")
addCommandAlias("fmtCheck", "scalafmtCheckAll; scalafmtSbtCheck")
