addSbtPlugin("org.scalameta"     % "sbt-scalafmt"        % "2.6.2")
addSbtPlugin("org.playframework" % "sbt-plugin"          % "3.1.0-M9")
addSbtPlugin("com.github.sbt"    % "sbt-native-packager" % "1.11.7")
addSbtPlugin("com.timushev.sbt"  % "sbt-updates"         % "0.7.0")
// addSbtPlugin("com.github.sbt" % "sbt-javaagent" % "0.1.8")

// Metals' metals.sbt brings sbt-debug-adapter, whose scala-debug-adapter_3 depends
// on scalameta parsers_2.13 for its 2.13 expression compiler, while Play's
// sbt-plugin brings twirl-compiler_3, which depends on parsers_3. Both belong on
// the meta-build classpath. sbt 2.0.9 turns that cross-version clash into a hard
// error, so keep it at warning level.
ThisBuild / conflictWarning := ConflictWarning.disable
