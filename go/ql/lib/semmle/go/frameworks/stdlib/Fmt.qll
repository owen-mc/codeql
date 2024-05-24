/**
 * Provides classes modeling security-relevant aspects of the `fmt` package.
 */

import go

/** Provides models of commonly used functions in the `fmt` package. */
module Fmt {
  /**
   * The `Sprint` or `Append` functions or one of their variants.
   *
   * DEPRECATED: Use AppenderOrSprinterFunc instead.
   */
  deprecated class AppenderOrSprinter extends TaintTracking::FunctionModel {
    AppenderOrSprinter() { this.hasQualifiedName("fmt", ["Append", "Sprint"] + ["", "f", "ln"]) }

    override predicate hasTaintFlow(FunctionInput inp, FunctionOutput outp) {
      inp.isParameter(_) and outp.isResult()
    }
  }

  /** The `Sprint` or `Append` functions or one of their variants. */
  class AppenderOrSprinterFunc extends Function {
    AppenderOrSprinterFunc() {
      this.hasQualifiedName("fmt", ["Append", "Sprint"] + ["", "f", "ln"])
    }
  }

  /** The `Sprint` function or one of its variants. */
  class Sprinter extends AppenderOrSprinterFunc {
    Sprinter() { this.getName().matches("Sprint%") }
  }

  /** The `Print` function or one of its variants. */
  class Printer extends Function {
    Printer() { this.hasQualifiedName("fmt", ["Print", "Printf", "Println"]) }
  }

  /** A call to `Print` or similar. */
  private class PrintCall extends LoggerCall::Range, DataFlow::CallNode {
    PrintCall() { this.getTarget() instanceof Printer }

    override DataFlow::Node getAMessageComponent() { result = this.getASyntacticArgument() }
  }

  private class FmtStringFormatter extends StringOps::Formatting::Range {
    int argOffset;

    FmtStringFormatter() {
      exists(string fname |
        this.hasQualifiedName("fmt", fname) and
        (
          fname = ["Printf", "Sprintf"] and argOffset = 0
          or
          fname = "Fprintf" and argOffset = 1
        )
      )
    }

    override int getFormatStringIndex() { result = argOffset }
  }

  /** The `Scan` function or one of its variants, all of which read from `os.Stdin`. */
  class Scanner extends Function {
    Scanner() { this.hasQualifiedName("fmt", ["Scan", "Scanf", "Scanln"]) }
  }

  /**
   * The `Fscan` function or one of its variants,
   * all of which read from a specified `io.Reader`.
   */
  class FScanner extends Function {
    FScanner() { this.hasQualifiedName("fmt", ["Fscan", "Fscanf", "Fscanln"]) }

    /**
     * Gets the node corresponding to the `io.Reader`
     * argument provided in the call.
     */
    FunctionInput getReader() { result.isParameter(0) }
  }
}
