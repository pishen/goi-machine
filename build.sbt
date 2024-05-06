name := "goi-machine"

scalaVersion := "2.13.13"

val tapirV = "1.10.6"

libraryDependencies ++= Seq(
  "com.softwaremill.sttp.tapir" %% "tapir-core" % tapirV,
  "com.softwaremill.sttp.tapir" %% "tapir-netty-server" % tapirV,
  "ch.qos.logback" % "logback-classic" % "1.5.6",
  "com.typesafe.scala-logging" %% "scala-logging" % "3.9.4"
)

scalacOptions ++= Seq(
  "-deprecation",
  "-feature",
  "-language:higherKinds",
  "-language:reflectiveCalls",
  "-Ywarn-unused:implicits",
  "-Ywarn-unused:imports",
  "-Ywarn-unused:locals",
  "-Ywarn-unused:params"
)

Compile / console / scalacOptions --= Seq("-Ywarn-unused:imports")

// assembly
assembly / mainClass := Some("core.Main")

assembly / assemblyJarName := "app.jar"

assembly / assemblyMergeStrategy := {
  case "META-INF/io.netty.versions.properties" => MergeStrategy.first
  case "module-info.class"                     => MergeStrategy.first
  case x =>
    val oldStrategy = (assembly / assemblyMergeStrategy).value
    oldStrategy(x)
}

// App Engine
lazy val deploy = taskKey[Unit]("Deploy to App Engine")

deploy := {
  val deployDir = target.value / "deploy"
  IO.copyFile(assembly.value, deployDir / "app.jar")
  val yamlDestPath = deployDir / "app.yaml"
  IO.copyFile(baseDirectory.value / "app.yaml", yamlDestPath)

  import sys.process._
  val cmd = Seq("gcloud", "app", "deploy", yamlDestPath.toString, "--project", "goi-machine", "-v", "main")
  println(cmd.mkString(" "))
  assert(cmd.! == 0)
}
