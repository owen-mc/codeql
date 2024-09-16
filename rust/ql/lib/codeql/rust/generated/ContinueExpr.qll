// generated by codegen
/**
 * This module provides the generated definition of `ContinueExpr`.
 * INTERNAL: Do not import directly.
 */

private import codeql.rust.generated.Synth
private import codeql.rust.generated.Raw
import codeql.rust.elements.Expr
import codeql.rust.elements.Label

/**
 * INTERNAL: This module contains the fully generated definition of `ContinueExpr` and should not
 * be referenced directly.
 */
module Generated {
  /**
   * A continue expression. For example:
   * ```
   * loop {
   *     if not_ready() {
   *         continue;
   *     }
   * }
   * ```
   * ```
   * 'label: loop {
   *     if not_ready() {
   *         continue 'label;
   *     }
   * }
   * ```
   * INTERNAL: Do not reference the `Generated::ContinueExpr` class directly.
   * Use the subclass `ContinueExpr`, where the following predicates are available.
   */
  class ContinueExpr extends Synth::TContinueExpr, Expr {
    override string getAPrimaryQlClass() { result = "ContinueExpr" }

    /**
     * Gets the label of this continue expression, if it exists.
     */
    Label getLabel() {
      result =
        Synth::convertLabelFromRaw(Synth::convertContinueExprToRaw(this)
              .(Raw::ContinueExpr)
              .getLabel())
    }

    /**
     * Holds if `getLabel()` exists.
     */
    final predicate hasLabel() { exists(this.getLabel()) }
  }
}
