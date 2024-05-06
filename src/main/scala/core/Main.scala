package core

import com.typesafe.scalalogging.StrictLogging
import sttp.tapir._
import sttp.tapir.server.netty.NettyFutureServer

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

object Main extends StrictLogging {
  def main(args: Array[String]): Unit = {
    val hello = endpoint.get
      .in("hello")
      .in(query[String]("name"))
      .out(stringBody)
      .serverLogic(name =>
        Future.successful[Either[Unit, String]](Right(s"hello, $name"))
      )

    NettyFutureServer()
      .port(sys.env.getOrElse("PORT", "8080").toInt)
      .addEndpoint(hello)
      .start()
      .foreach { binding =>
        logger.info(s"Server started at port ${binding.port}")
      }
  }
}
