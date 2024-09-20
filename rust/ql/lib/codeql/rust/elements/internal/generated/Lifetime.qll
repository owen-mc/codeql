// generated by codegen, do not edit
/**
 * This module provides the generated definition of `Lifetime`.
 * INTERNAL: Do not import directly.
 */

private import codeql.rust.elements.internal.generated.Synth
private import codeql.rust.elements.internal.generated.Raw
import codeql.rust.elements.internal.AstNodeImpl::Impl as AstNodeImpl

/**
 * INTERNAL: This module contains the fully generated definition of `Lifetime` and should not
 * be referenced directly.
 */
module Generated {
  /**
   * A Lifetime. For example:
   * ```rust
   * todo!()
   * ```
   * INTERNAL: Do not reference the `Generated::Lifetime` class directly.
   * Use the subclass `Lifetime`, where the following predicates are available.
   */
  class Lifetime extends Synth::TLifetime, AstNodeImpl::AstNode {
    override string getAPrimaryQlClass() { result = "Lifetime" }

    /**
     * Gets the text of this lifetime, if it exists.
     */
    string getText() { result = Synth::convertLifetimeToRaw(this).(Raw::Lifetime).getText() }

    /**
     * Holds if `getText()` exists.
     */
    final predicate hasText() { exists(this.getText()) }
  }
}
