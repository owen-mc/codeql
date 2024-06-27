// generated by codegen/codegen.py
/**
 * This module provides the generated definition of `SwitchStmt`.
 * INTERNAL: Do not import directly.
 */

private import codeql.swift.generated.Synth
private import codeql.swift.generated.Raw
import codeql.swift.elements.stmt.CaseStmt
import codeql.swift.elements.expr.Expr
import codeql.swift.elements.stmt.LabeledStmt

/**
 * INTERNAL: This module contains the fully generated definition of `SwitchStmt` and should not
 * be referenced directly.
 */
module Generated {
  /**
   * INTERNAL: Do not reference the `Generated::SwitchStmt` class directly.
   * Use the subclass `SwitchStmt`, where the following predicates are available.
   */
  class SwitchStmt extends Synth::TSwitchStmt, LabeledStmt {
    override string getAPrimaryQlClass() { result = "SwitchStmt" }

    /**
     * Gets the expression of this switch statement.
     *
     * This includes nodes from the "hidden" AST. It can be overridden in subclasses to change the
     * behavior of both the `Immediate` and non-`Immediate` versions.
     */
    Expr getImmediateExpr() {
      result =
        Synth::convertExprFromRaw(Synth::convertSwitchStmtToRaw(this).(Raw::SwitchStmt).getExpr())
    }

    /**
     * Gets the expression of this switch statement.
     */
    final Expr getExpr() {
      exists(Expr immediate |
        immediate = this.getImmediateExpr() and
        result = immediate.resolve()
      )
    }

    /**
     * Gets the `index`th case of this switch statement (0-based).
     */
    CaseStmt getCase(int index) {
      result =
        Synth::convertCaseStmtFromRaw(Synth::convertSwitchStmtToRaw(this)
              .(Raw::SwitchStmt)
              .getCase(index))
    }

    /**
     * Gets any of the cases of this switch statement.
     */
    final CaseStmt getACase() { result = this.getCase(_) }

    /**
     * Gets the number of cases of this switch statement.
     */
    final int getNumberOfCases() { result = count(int i | exists(this.getCase(i))) }
  }
}
