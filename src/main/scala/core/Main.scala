package core

import cats.syntax.all._
import com.typesafe.config.ConfigFactory
import com.typesafe.scalalogging.StrictLogging
import io.circe.generic.auto._
import io.circe.syntax._
import pdi.jwt.JwtAlgorithm
import pdi.jwt.JwtCirce
import scalatags.Text.all.{header => _, _}
import scalatags.Text.svgAttrs
import scalatags.Text.svgTags
import sttp.client3._
import sttp.client3.circe._
import sttp.model.HeaderNames
import sttp.model.StatusCode
import sttp.model.Uri
import sttp.model.headers.CookieValueWithMeta
import sttp.monad.FutureMonad
import sttp.tapir._
import sttp.tapir.files._
import sttp.tapir.server.netty.NettyFutureServer

import java.time.Instant
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

object Main extends App with StrictLogging {
  val conf = ConfigFactory.load()
  val jwtKey = conf.getString("jwt.secretKey")
  val clientId = conf.getString("oauth.id")
  val clientSecret = conf.getString("oauth.secret")

  val sttpBackend = HttpClientFutureBackend()

  case class User(id: String, email: String)
  def decodeUser(token: String) = JwtCirce
    .decodeJson(token, jwtKey, Seq(JwtAlgorithm.HS256))
    .toEither
    .flatMap(_.as[User])
    .left
    .map(_.getMessage())

  val secureEndpoint = endpoint
    .securityIn(auth.apiKey(cookie[String]("token")))
    .errorOut(stringBody)
    .serverSecurityLogicPure(decodeUser)

  val tagBody =
    stringBody.map(_ => div(sys.error("can't used as input")))(_.toString)

  val menu = endpoint.get
    .in("menu")
    .in(cookie[Option[String]]("token"))
    .in(header[String]("HX-Current-URL"))
    .out(tagBody)
    .errorOut(stringBody)
    .serverLogicPure[Future] { case (tokenOpt, currentUrl) =>
      val btnStyle =
        "rounded-md px-3 py-2 text-sm font-semibold text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 hover:bg-gray-50"
      tokenOpt match {
        case None =>
          val callbackUri = Uri.unsafeParse(currentUrl).withPath("callback")
          val authUri =
            uri"https://accounts.google.com/o/oauth2/v2/auth?client_id=$clientId&redirect_uri=$callbackUri&response_type=code&scope=email"
          a(cls := btnStyle, href := authUri.toString, "Sign in")
            .asRight[String]
        case Some(token) =>
          decodeUser(token).map(user =>
            div(
              cls := "relative inline-block text-left",
              attr("x-data") := "{isOpen:false}",
              button(
                cls := btnStyle + " inline-flex w-full justify-center gap-x-1.5",
                attr("x-on:click") := "isOpen = !isOpen",
                user.email.stripSuffix("@gmail.com"),
                svgTags.svg(
                  cls := "-mr-1 h-5 w-5 text-gray-400",
                  svgAttrs.viewBox := "0 0 20 20",
                  svgAttrs.fill := "currentColor",
                  svgTags.path(
                    svgAttrs.fillRule := "evenodd",
                    svgAttrs.d := "M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z",
                    svgAttrs.clipRule := "evenodd"
                  )
                )
              ),
              div(
                cls := "absolute right-0 z-10 mt-2 w-56 origin-top-right rounded-md bg-white shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none",
                attr("x-show") := "isOpen",
                attr("x-transition:enter") :=
                  "transition ease-out duration-100",
                attr("x-transition:enter-start") :=
                  "transform opacity-0 scale-95",
                attr("x-transition:enter-end") :=
                  "transform opacity-100 scale-100",
                attr("x-transition:leave") := "transition ease-in duration-75",
                attr("x-transition:leave-start") :=
                  "transform opacity-100 scale-100",
                attr("x-transition:leave-end") :=
                  "transform opacity-0 scale-95",
                div(
                  cls := "py-1",
                  button(
                    cls := "text-gray-700 block px-4 py-2 text-sm hover:bg-gray-50 w-full text-left",
                    "追加"
                  ),
                  a(
                    href := "/logout",
                    cls := "text-gray-700 block px-4 py-2 text-sm hover:bg-gray-50",
                    "Logout"
                  )
                )
              )
            )
          )
      }
    }

  case class AccessTokenResp(access_token: String)
  val callback = endpoint.get
    .in("callback")
    .in(query[String]("code"))
    .in(header[String](HeaderNames.Host))
    .out(statusCode(StatusCode.Found))
    .out(header[String](HeaderNames.Location))
    .out(setCookie("token"))
    .serverLogic { case (code, host) =>
      val redirectUri = if (host.startsWith("localhost")) {
        uri"http://$host/callback"
      } else {
        uri"https://$host/callback"
      }
      for {
        accessToken <- basicRequest
          .post(uri"https://oauth2.googleapis.com/token")
          .body(
            "code" -> code,
            "client_id" -> clientId,
            "client_secret" -> clientSecret,
            "redirect_uri" -> redirectUri.toString,
            "grant_type" -> "authorization_code"
          )
          .response(asJson[AccessTokenResp].getRight)
          .send(sttpBackend)
          .map(_.body.access_token)
        user <- basicRequest
          .get(
            uri"https://www.googleapis.com/userinfo/v2/me?access_token=$accessToken"
          )
          .response(asJson[User].getRight)
          .send(sttpBackend)
          .map(_.body)
      } yield {
        val token = JwtCirce.encode(user.asJson, jwtKey, JwtAlgorithm.HS256)
        val cookie = CookieValueWithMeta.unsafeApply(token, httpOnly = true)
        ("/", cookie).asRight[Unit]
      }
    }

  val logout = endpoint.get
    .in("logout")
    .out(statusCode(StatusCode.Found))
    .out(header[String](HeaderNames.Location))
    .out(setCookie("token"))
    .serverLogicPure[Future] { _ =>
      val cookie = CookieValueWithMeta.unsafeApply(
        "deleted",
        expires = Some(Instant.EPOCH)
      )
      ("/", cookie).asRight[Unit]
    }

  val files = staticResourcesGetEndpoint(emptyInput)
    .out(
      header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    )
    .serverLogic {
      Resources.get(classOf[App].getClassLoader(), "public")(new FutureMonad())
    }

  NettyFutureServer()
    .port(sys.env.getOrElse("PORT", "8080").toInt)
    .addEndpoints(
      List(menu, callback, logout, files)
    )
    .start()
    .foreach { binding =>
      logger.info(s"Server started at port ${binding.port}")
    }
}
