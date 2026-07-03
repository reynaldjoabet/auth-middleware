package auth

import java.lang.reflect.Modifier

import munit.FunSuite

/** The Scala [[Scopes]] object is the source of truth for the scope catalogue;
  * the Java [[ScopeConstants]] duplicates the strings because annotation
  * members must be compile-time constants. This test fails the build on any
  * drift.
  */
class ScopeConstantsParitySpec extends FunSuite {

  private val scalaScopes: Set[String] =
    Scopes.all.map(s => s.value: String).toSet

  private val javaConstants: Set[String] =
    classOf[ScopeConstants].getFields.toList
      .filter(f => Modifier.isStatic(f.getModifiers))
      .map(_.get(null).asInstanceOf[String])
      .toSet

  test("ScopeConstants mirrors Scopes.all exactly") {
    assertEquals(javaConstants, scalaScopes)
  }
}
