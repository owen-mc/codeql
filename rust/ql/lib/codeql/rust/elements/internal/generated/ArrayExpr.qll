// generated by codegen, do not edit
/**
 * This module provides the generated definition of `ArrayExpr`.
 * INTERNAL: Do not import directly.
 */

private import codeql.rust.elements.internal.generated.Synth
private import codeql.rust.elements.internal.generated.Raw
import codeql.rust.elements.internal.ExprImpl::Impl as ExprImpl

/**
 * INTERNAL: This module contains the fully generated definition of `ArrayExpr` and should not
 * be referenced directly.
 */
module Generated {
  /**
   * An array expression. For example:
   * ```rust
   * [1, 2, 3];
   * [1; 10];
   * ```
   * INTERNAL: Do not reference the `Generated::ArrayExpr` class directly.
   * Use the subclass `ArrayExpr`, where the following predicates are available.
   */
  class ArrayExpr extends Synth::TArrayExpr, ExprImpl::Expr { }
}
