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
      .out(stringBody)
      .serverLogic(_ => Future.successful[Either[Unit, String]](Right("hello")))

    NettyFutureServer().addEndpoint(hello).start().foreach { binding =>
      logger.info(s"Server started at port ${binding.port}")
    }
  }
}
