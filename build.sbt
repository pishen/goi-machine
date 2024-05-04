name := "goi-machine2"

scalaVersion := "2.13.13"

val tapirV = "1.10.6"

libraryDependencies ++= Seq(
  "com.softwaremill.sttp.tapir" %% "tapir-core" % tapirV,
  "com.softwaremill.sttp.tapir" %% "tapir-netty-server" % tapirV,
  "ch.qos.logback" % "logback-classic" % "1.5.6",
  "com.typesafe.scala-logging" %% "scala-logging" % "3.9.4"
)
