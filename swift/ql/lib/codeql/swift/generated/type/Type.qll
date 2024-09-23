// generated by codegen/codegen.py, do not edit
/**
 * This module provides the generated definition of `Type`.
 * INTERNAL: Do not import directly.
 */

private import codeql.swift.generated.Synth
private import codeql.swift.generated.Raw
import codeql.swift.elements.internal.ElementImpl::Impl as ElementImpl
import codeql.swift.elements.type.Type

/**
 * INTERNAL: This module contains the fully generated definition of `Type` and should not
 * be referenced directly.
 */
module Generated {
  /**
   * INTERNAL: Do not reference the `Generated::Type` class directly.
   * Use the subclass `Type`, where the following predicates are available.
   */
  class Type extends Synth::TType, ElementImpl::Element {
    /**
     * Gets the name of this type.
     */
    string getName() { result = Synth::convertTypeToRaw(this).(Raw::Type).getName() }

    /**
     * Gets the canonical type of this type.
     *
     * This includes nodes from the "hidden" AST. It can be overridden in subclasses to change the
     * behavior of both the `Immediate` and non-`Immediate` versions.
     */
    Type getImmediateCanonicalType() {
      result =
        Synth::convertTypeFromRaw(Synth::convertTypeToRaw(this).(Raw::Type).getCanonicalType())
    }

    /**
     * Gets the canonical type of this type.
     *
     * This is the unique type we get after resolving aliases and desugaring. For example, given
     * ```
     * typealias MyInt = Int
     * ```
     * then `[MyInt?]` has the canonical type `Array<Optional<Int>>`.
     */
    final Type getCanonicalType() {
      exists(Type immediate |
        immediate = this.getImmediateCanonicalType() and
        if exists(this.getResolveStep()) then result = immediate else result = immediate.resolve()
      )
    }
  }
}
