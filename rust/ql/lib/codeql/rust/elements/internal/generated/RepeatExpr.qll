// generated by codegen, do not edit
/**
 * This module provides the generated definition of `RepeatExpr`.
 * INTERNAL: Do not import directly.
 */

private import codeql.rust.elements.internal.generated.Synth
private import codeql.rust.elements.internal.generated.Raw
import codeql.rust.elements.internal.ArrayExprImpl::Impl as ArrayExprImpl
import codeql.rust.elements.Expr

/**
 * INTERNAL: This module contains the fully generated definition of `RepeatExpr` and should not
 * be referenced directly.
 */
module Generated {
  /**
   * A repeat expression. For example:
   * ```rust
   * [1; 10];
   * ```
   * INTERNAL: Do not reference the `Generated::RepeatExpr` class directly.
   * Use the subclass `RepeatExpr`, where the following predicates are available.
   */
  class RepeatExpr extends Synth::TRepeatExpr, ArrayExprImpl::ArrayExpr {
    override string getAPrimaryQlClass() { result = "RepeatExpr" }

    /**
     * Gets the initializer of this repeat expression.
     */
    Expr getInitializer() {
      result =
        Synth::convertExprFromRaw(Synth::convertRepeatExprToRaw(this)
              .(Raw::RepeatExpr)
              .getInitializer())
    }

    /**
     * Gets the repeat of this repeat expression.
     */
    Expr getRepeat() {
      result =
        Synth::convertExprFromRaw(Synth::convertRepeatExprToRaw(this).(Raw::RepeatExpr).getRepeat())
    }
  }
}
