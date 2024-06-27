// generated by codegen/codegen.py
/**
 * This module provides the generated definition of `OptionalSomePattern`.
 * INTERNAL: Do not import directly.
 */

private import codeql.swift.generated.Synth
private import codeql.swift.generated.Raw
import codeql.swift.elements.pattern.Pattern

/**
 * INTERNAL: This module contains the fully generated definition of `OptionalSomePattern` and should not
 * be referenced directly.
 */
module Generated {
  /**
   * INTERNAL: Do not reference the `Generated::OptionalSomePattern` class directly.
   * Use the subclass `OptionalSomePattern`, where the following predicates are available.
   */
  class OptionalSomePattern extends Synth::TOptionalSomePattern, Pattern {
    override string getAPrimaryQlClass() { result = "OptionalSomePattern" }

    /**
     * Gets the sub pattern of this optional some pattern.
     *
     * This includes nodes from the "hidden" AST. It can be overridden in subclasses to change the
     * behavior of both the `Immediate` and non-`Immediate` versions.
     */
    Pattern getImmediateSubPattern() {
      result =
        Synth::convertPatternFromRaw(Synth::convertOptionalSomePatternToRaw(this)
              .(Raw::OptionalSomePattern)
              .getSubPattern())
    }

    /**
     * Gets the sub pattern of this optional some pattern.
     */
    final Pattern getSubPattern() {
      exists(Pattern immediate |
        immediate = this.getImmediateSubPattern() and
        if exists(this.getResolveStep()) then result = immediate else result = immediate.resolve()
      )
    }
  }
}
