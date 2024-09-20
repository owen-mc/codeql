// generated by codegen, do not edit
/**
 * This module provides the generated definition of `FormatArgsArg`.
 * INTERNAL: Do not import directly.
 */

private import codeql.rust.elements.internal.generated.Synth
private import codeql.rust.elements.internal.generated.Raw
import codeql.rust.elements.internal.AstNodeImpl::Impl as AstNodeImpl
import codeql.rust.elements.Expr
import codeql.rust.elements.Name

/**
 * INTERNAL: This module contains the fully generated definition of `FormatArgsArg` and should not
 * be referenced directly.
 */
module Generated {
  /**
   * A FormatArgsArg. For example:
   * ```rust
   * todo!()
   * ```
   * INTERNAL: Do not reference the `Generated::FormatArgsArg` class directly.
   * Use the subclass `FormatArgsArg`, where the following predicates are available.
   */
  class FormatArgsArg extends Synth::TFormatArgsArg, AstNodeImpl::AstNode {
    override string getAPrimaryQlClass() { result = "FormatArgsArg" }

    /**
     * Gets the expression of this format arguments argument, if it exists.
     */
    Expr getExpr() {
      result =
        Synth::convertExprFromRaw(Synth::convertFormatArgsArgToRaw(this)
              .(Raw::FormatArgsArg)
              .getExpr())
    }

    /**
     * Holds if `getExpr()` exists.
     */
    final predicate hasExpr() { exists(this.getExpr()) }

    /**
     * Gets the name of this format arguments argument, if it exists.
     */
    Name getName() {
      result =
        Synth::convertNameFromRaw(Synth::convertFormatArgsArgToRaw(this)
              .(Raw::FormatArgsArg)
              .getName())
    }

    /**
     * Holds if `getName()` exists.
     */
    final predicate hasName() { exists(this.getName()) }
  }
}
