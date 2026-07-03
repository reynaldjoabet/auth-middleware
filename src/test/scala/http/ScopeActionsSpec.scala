package http.actions

import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionStage

import scala.jdk.CollectionConverters.*

import auth.annotation.{RequireAnyScope, RequireScope}
import auth.{FeatureChecker, Principal, SecurityAttrs}
import com.nimbusds.jwt.JWTClaimsSet
import munit.FunSuite
import play.mvc.{Action, Http, Result, Results}

/** Exercises [[ScopeCheckAction]] (ALL semantics) and [[AnyScopeCheckAction]]
  * (ANY semantics) against hand-built requests, asserting the RFC 6750/9470
  * challenge shapes the middleware promises.
  */
class ScopeActionsSpec extends FunSuite {

  // ── carriers: the annotation instances under test ──────────────────────
  @RequireScope(Array("billing.invoices.read"))
  private class SingleCarrier
  @RequireScope(Array("billing.invoices.read", "audit.events.read"))
  private class AllCarrier
  @RequireScope(
    value = Array("reports.exports.read"),
    requireUserIdentity = false
  )
  private class MachineCarrier
  @RequireScope(
    value = Array("billing.invoices.read"),
    requiredFeature = "invoicing"
  )
  private class GatedCarrier
  @RequireAnyScope(Array("billing.invoices.read", "billing.invoices.manage"))
  private class AnyCarrier
  @RequireAnyScope(Array())
  private class EmptyAnyCarrier

  private val okDelegate: Action[?] = new Action.Simple {
    override def call(req: Http.Request): CompletionStage[Result] =
      CompletableFuture.completedFuture(Results.ok("through"))
  }

  private val noFeatures: FeatureChecker = (_, _) => false

  private def scopeAction(
      carrier: Class[?],
      features: FeatureChecker = noFeatures
  ): ScopeCheckAction = {
    val action = new ScopeCheckAction(features)
    action.configuration = carrier.getAnnotation(classOf[RequireScope])
    action.delegate = okDelegate
    action
  }

  private def anyScopeAction(
      carrier: Class[?],
      features: FeatureChecker = noFeatures
  ): AnyScopeCheckAction = {
    val action = new AnyScopeCheckAction(features)
    action.configuration = carrier.getAnnotation(classOf[RequireAnyScope])
    action.delegate = okDelegate
    action
  }

  private def principal(
      scopes: Set[String],
      subject: String = "user-123",
      clientId: String = "mobile-app"
  ): Principal =
    new Principal(
      subject,
      clientId,
      scopes.asJava,
      null,
      Set.empty[String].asJava,
      null,
      new JWTClaimsSet.Builder().subject(subject).build()
    )

  private def request(p: Option[Principal]): Http.Request = {
    val base = new Http.RequestBuilder().method("GET").uri("/x").build()
    p.fold(base)(pr => base.addAttr(SecurityAttrs.PRINCIPAL, pr))
  }

  private def run(action: Action[?], req: Http.Request): Result =
    action.call(req).toCompletableFuture.join()

  private def challenge(r: Result): String =
    r.headers().asScala.getOrElse(Http.HeaderNames.WWW_AUTHENTICATE, "")

  // ── ScopeCheckAction (ALL) ──────────────────────────────────────────────

  test("no principal → 401 invalid_token") {
    val r = run(scopeAction(classOf[SingleCarrier]), request(None))
    assertEquals(r.status(), 401)
    assert(challenge(r).contains("invalid_token"))
  }

  test("missing scope → 403 advertising the required scope") {
    val r = run(
      scopeAction(classOf[SingleCarrier]),
      request(Some(principal(Set("accounts.read"))))
    )
    assertEquals(r.status(), 403)
    assert(challenge(r).contains("insufficient_scope"))
    assert(challenge(r).contains("billing.invoices.read"))
  }

  test("ALL semantics: one of two scopes → 403 advertising the full set") {
    val r = run(
      scopeAction(classOf[AllCarrier]),
      request(Some(principal(Set("billing.invoices.read"))))
    )
    assertEquals(r.status(), 403)
    assert(challenge(r).contains("billing.invoices.read audit.events.read"))
  }

  test("ALL semantics: both scopes present → passes through") {
    val r = run(
      scopeAction(classOf[AllCarrier]),
      request(
        Some(principal(Set("billing.invoices.read", "audit.events.read")))
      )
    )
    assertEquals(r.status(), 200)
  }

  test(
    "client-credentials token (sub == client_id) → 403 insufficient_user_authentication"
  ) {
    val r = run(
      scopeAction(classOf[SingleCarrier]),
      request(
        Some(
          principal(
            Set("billing.invoices.read"),
            subject = "svc-1",
            clientId = "svc-1"
          )
        )
      )
    )
    assertEquals(r.status(), 403)
    assert(challenge(r).contains("insufficient_user_authentication"))
  }

  test("requireUserIdentity = false admits machine tokens") {
    val r = run(
      scopeAction(classOf[MachineCarrier]),
      request(
        Some(
          principal(
            Set("reports.exports.read"),
            subject = "svc-1",
            clientId = "svc-1"
          )
        )
      )
    )
    assertEquals(r.status(), 200)
  }

  test("feature gate consults the FeatureChecker and fails closed") {
    val denied = run(
      scopeAction(classOf[GatedCarrier]),
      request(Some(principal(Set("billing.invoices.read"))))
    )
    assertEquals(denied.status(), 403)

    val granted = run(
      scopeAction(
        classOf[GatedCarrier],
        (feature, _) => feature == "invoicing"
      ),
      request(Some(principal(Set("billing.invoices.read"))))
    )
    assertEquals(granted.status(), 200)
  }

  // ── AnyScopeCheckAction (ANY) ───────────────────────────────────────────

  test("any-of passes when one accepted scope is present") {
    val r = run(
      anyScopeAction(classOf[AnyCarrier]),
      request(Some(principal(Set("billing.invoices.manage"))))
    )
    assertEquals(r.status(), 200)
  }

  test("any-of rejects when none are present, advertising every option") {
    val r = run(
      anyScopeAction(classOf[AnyCarrier]),
      request(Some(principal(Set("accounts.read"))))
    )
    assertEquals(r.status(), 403)
    assert(
      challenge(r).contains("billing.invoices.read billing.invoices.manage")
    )
  }

  test("any-of with no principal → 401") {
    val r = run(anyScopeAction(classOf[AnyCarrier]), request(None))
    assertEquals(r.status(), 401)
  }

  test("any-of enforces the shared user-identity policy") {
    val r = run(
      anyScopeAction(classOf[AnyCarrier]),
      request(
        Some(
          principal(
            Set("billing.invoices.manage"),
            subject = "svc-1",
            clientId = "svc-1"
          )
        )
      )
    )
    assertEquals(r.status(), 403)
    assert(challenge(r).contains("insufficient_user_authentication"))
  }

  test("empty any-of list fails closed") {
    val r = run(
      anyScopeAction(classOf[EmptyAnyCarrier]),
      request(Some(principal(Set("billing.invoices.read"))))
    )
    assertEquals(r.status(), 403)
  }
}
