import org.typelevel.sbt.tpolecat.DevMode

name := "goi-machine"

scalaVersion := "2.13.13"

val sttpV = "3.9.6"
val tapirV = "1.10.6"
val circeV = "0.14.1"

libraryDependencies ++= Seq(
  "ch.qos.logback" % "logback-classic" % "1.5.6",
  "com.github.jwt-scala" %% "jwt-circe" % "10.0.1",
  "com.lihaoyi" %% "scalatags" % "0.8.2",
  "com.softwaremill.sttp.client3" %% "core" % sttpV,
  "com.softwaremill.sttp.client3" %% "circe" % sttpV,
  "com.softwaremill.sttp.tapir" %% "tapir-core" % tapirV,
  "com.softwaremill.sttp.tapir" %% "tapir-netty-server" % tapirV,
  "com.softwaremill.sttp.tapir" %% "tapir-json-circe" % tapirV,
  "com.softwaremill.sttp.tapir" %% "tapir-files" % tapirV,
  "com.typesafe" % "config" % "1.4.3",
  "com.typesafe.scala-logging" %% "scala-logging" % "3.9.4",
  "io.circe" %% "circe-core" % circeV,
  "io.circe" %% "circe-generic" % circeV,
  "io.circe" %% "circe-parser" % circeV,
  "net.pishen" %% "store4s-rpc" % "0.20.0"
)

ThisBuild / tpolecatDefaultOptionsMode := DevMode

// assembly
assembly / mainClass := Some("core.Main")

assembly / assemblyJarName := "app.jar"

assembly / assemblyMergeStrategy := {
  case "META-INF/io.netty.versions.properties" => MergeStrategy.first
  case PathList(ps @ _*) if ps.last == "module-info.class" =>
    MergeStrategy.first
  case x =>
    val oldStrategy = (assembly / assemblyMergeStrategy).value
    oldStrategy(x)
}

// App Engine
lazy val prepareForDeploy = taskKey[Unit]("Prepare for deploy")

prepareForDeploy := {
  val deployDir = target.value / "deploy"
  IO.copyFile(assembly.value, deployDir / "app.jar")
  val yamlDestPath = deployDir / "app.yaml"
  IO.copyFile(baseDirectory.value / "app.yaml", yamlDestPath)
}
