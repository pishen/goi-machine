package core

import cats.syntax.all._
import com.typesafe.config.ConfigFactory
import com.typesafe.scalalogging.StrictLogging
import io.circe.generic.auto._
import io.circe.syntax._
import pdi.jwt.JwtAlgorithm
import pdi.jwt.JwtCirce
import store4s.rpc.{EncoderOps => Store4sEncoderOps, _}
import sttp.client3._
import sttp.client3.circe._
import sttp.model.HeaderNames
import sttp.model.StatusCode
import sttp.model.Uri
import sttp.model.headers.CookieValueWithMeta
import sttp.tapir._
import sttp.tapir.files._
import sttp.tapir.generic.auto._
import sttp.tapir.json.circe._
import sttp.tapir.server.netty.NettyFutureServer

import java.time.Instant
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future
import scala.io.Source
import scala.util.Random

object Main extends App with StrictLogging {
  val conf = ConfigFactory.load()
  val jwtKey = conf.getString("jwt.secretKey")
  val clientId = conf.getString("oauth.id")
  val clientSecret = conf.getString("oauth.secret")
  val origin = Uri.unsafeParse(
    if (conf.hasPath("origin")) conf.getString("origin")
    else "http://localhost:8080"
  )
  val callbackUri = origin.withPath("callback")

  val sttpBackend = HttpClientFutureBackend()

  val ds = Datastore()

  case class User(id: String, email: String)
  case class Me(user: Option[User])
  case class AccessTokenResp(access_token: String)
  case class Question(
      userId: String,
      question: String,
      answer: String,
      correctCount: Int = 0,
      lastTry: Long = 0
  )
  implicit val questionEnc: Encoder[Question] =
    Encoder.gen[Question].withName(q => q.userId + q.question)
  case class QA(question: String, answer: String)
  case class Quiz(
      question: String,
      answer: String,
      wrong: Boolean,
      message: String
  )

  def decodeUser(token: String) = JwtCirce
    .decodeJson(token, jwtKey, Seq(JwtAlgorithm.HS256))
    .toEither
    .flatMap(_.as[User])
    .left
    .map(_.getMessage())

  val secureEndpoint = endpoint
    .securityIn(auth.apiKey(cookie[String]("token")))
    .errorOut(stringBody)
    .serverSecurityLogicPure[User, Future](decodeUser)

  val me = endpoint.get
    .in("me")
    .in(cookie[Option[String]]("token"))
    .out(jsonBody[Me])
    .errorOut(stringBody)
    .serverLogicPure[Future](_.map(decodeUser).sequence.map(Me.apply))

  val login = endpoint.get
    .in("login")
    .out(statusCode(StatusCode.Found))
    .out(header[String](HeaderNames.Location))
    .serverLogicPure[Future] { _ =>
      uri"https://accounts.google.com/o/oauth2/v2/auth?client_id=$clientId&redirect_uri=$callbackUri&response_type=code&scope=email".toString
        .asRight[Unit]
    }

  val callback = endpoint.get
    .in("callback")
    .in(query[String]("code"))
    .out(statusCode(StatusCode.Found))
    .out(header[String](HeaderNames.Location))
    .out(setCookie("token"))
    .serverLogic { code =>
      for {
        accessToken <- basicRequest
          .post(uri"https://oauth2.googleapis.com/token")
          .body(
            "code" -> code,
            "client_id" -> clientId,
            "client_secret" -> clientSecret,
            "redirect_uri" -> callbackUri.toString,
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

  val questionPut = secureEndpoint.put
    .in("questions")
    .in(jsonBody[QA])
    .out(stringBody)
    .serverLogicSuccess { user => qa =>
      ds.transaction { tx =>
        for {
          q <- tx
            .lookupByName[Question](user.id + qa.question)
            .map(_.headOption)
            .map(
              _.getOrElse(Question(user.id, qa.question, qa.answer))
            )
          _ <-
            if (qa.answer == "") {
              tx.deleteByName[Question](user.id + qa.question)
            } else {
              tx.upsert(q.copy(answer = qa.answer).asEntity)
            }
        } yield "saved"
      }
    }

  // TODO
  val questionByQ = secureEndpoint.get
    .in("questions")
    .in(query[String]("q"))

  // TODO
  val questionByA = secureEndpoint.get
    .in("questions")
    .in(query[String]("a"))

  val quiz = secureEndpoint.put
    .in("quiz")
    .in(jsonBody[Quiz])
    .out(jsonBody[Quiz])
    .serverLogicSuccess { user => quiz =>
      def getNewQuiz() = Query
        .from[Question]
        .filter(_.userId == user.id)
        .filter(_.lastTry < System.currentTimeMillis() - 3600000)
        .sortBy(_.correctCount.asc)
        .take(10)
        .run(ds)
        .map { res =>
          Random.shuffle(res.toSeq).headOption match {
            case Some(q) =>
              Quiz(q.question, "", false, "")
            case None =>
              Quiz("", "", false, "All done, take a rest!")
          }
        }

      if (quiz.question != "") {
        for {
          q <- ds.lookupByName[Question](user.id + quiz.question).map(_.head)
          _ <- ds.update {
            val now = System.currentTimeMillis()
            val newQ = if (quiz.answer == q.answer && !quiz.wrong) {
              q.copy(correctCount = q.correctCount + 1, lastTry = now)
            } else {
              q.copy(correctCount = 0, lastTry = now)
            }
            newQ.asEntity
          }
          newQuiz <-
            if (quiz.answer == q.answer) {
              getNewQuiz().map(_.copy(message = "correct!"))
            } else {
              Future.successful(
                Quiz(q.question, q.answer, true, "wrong answer")
              )
            }
        } yield newQuiz
      } else {
        getNewQuiz()
      }
    }

  val files = staticResourcesGetServerEndpoint[Future]("files")(
    classOf[App].getClassLoader,
    "public"
  )

  val default = endpoint.get
    .out(htmlBodyUtf8)
    .out(
      header(
        HeaderNames.StrictTransportSecurity,
        "max-age=31536000; includeSubDomains"
      )
    )
    .serverLogicPure[Future](_ =>
      Source.fromResource("public/index.html").mkString.asRight[Unit]
    )

  NettyFutureServer()
    .port(sys.env.getOrElse("PORT", "8080").toInt)
    .addEndpoints(
      List(me, login, callback, logout, questionPut, quiz, files, default)
    )
    .start()
    .map { binding =>
      logger.info(s"Server started at port ${binding.port}")
    }
    .failed
    .foreach(t => logger.error("Error starting server", t))
}
