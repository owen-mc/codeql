// generated by codegen/codegen.py, do not edit
/**
 * This module provides the generated definition of `ExistentialMetatypeType`.
 * INTERNAL: Do not import directly.
 */

private import codeql.swift.generated.Synth
private import codeql.swift.generated.Raw
import codeql.swift.elements.type.internal.AnyMetatypeTypeImpl::Impl as AnyMetatypeTypeImpl

/**
 * INTERNAL: This module contains the fully generated definition of `ExistentialMetatypeType` and should not
 * be referenced directly.
 */
module Generated {
  /**
   * INTERNAL: Do not reference the `Generated::ExistentialMetatypeType` class directly.
   * Use the subclass `ExistentialMetatypeType`, where the following predicates are available.
   */
  class ExistentialMetatypeType extends Synth::TExistentialMetatypeType,
    AnyMetatypeTypeImpl::AnyMetatypeType
  {
    override string getAPrimaryQlClass() { result = "ExistentialMetatypeType" }
  }
}
