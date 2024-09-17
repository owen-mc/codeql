// generated by codegen/codegen.py, do not edit
/**
 * This module provides the generated definition of `DependentMemberType`.
 * INTERNAL: Do not import directly.
 */

private import codeql.swift.generated.Synth
private import codeql.swift.generated.Raw
import codeql.swift.elements.decl.AssociatedTypeDecl
import codeql.swift.elements.type.Type
import codeql.swift.elements.type.internal.TypeImpl::Impl as TypeImpl

/**
 * INTERNAL: This module contains the fully generated definition of `DependentMemberType` and should not
 * be referenced directly.
 */
module Generated {
  /**
   * INTERNAL: Do not reference the `Generated::DependentMemberType` class directly.
   * Use the subclass `DependentMemberType`, where the following predicates are available.
   */
  class DependentMemberType extends Synth::TDependentMemberType, TypeImpl::Type {
    override string getAPrimaryQlClass() { result = "DependentMemberType" }

    /**
     * Gets the base type of this dependent member type.
     *
     * This includes nodes from the "hidden" AST. It can be overridden in subclasses to change the
     * behavior of both the `Immediate` and non-`Immediate` versions.
     */
    Type getImmediateBaseType() {
      result =
        Synth::convertTypeFromRaw(Synth::convertDependentMemberTypeToRaw(this)
              .(Raw::DependentMemberType)
              .getBaseType())
    }

    /**
     * Gets the base type of this dependent member type.
     */
    final Type getBaseType() {
      exists(Type immediate |
        immediate = this.getImmediateBaseType() and
        if exists(this.getResolveStep()) then result = immediate else result = immediate.resolve()
      )
    }

    /**
     * Gets the associated type declaration of this dependent member type.
     */
    AssociatedTypeDecl getAssociatedTypeDecl() {
      result =
        Synth::convertAssociatedTypeDeclFromRaw(Synth::convertDependentMemberTypeToRaw(this)
              .(Raw::DependentMemberType)
              .getAssociatedTypeDecl())
    }
  }
}
