/**
 * Provides classes for working with untrusted flow sources from the `github.com/gin-contrib/cors` package.
 */

import go

module GinCors {
  /** Gets the package name `github.com/gin-gonic/gin`. */
  string packagePath() { result = package("github.com/gin-contrib/cors", "") }

  /**
   * New function create a new gin Handler that passed to gin as middleware
   */
  class New extends Function {
    New() { exists(Function f | f.hasQualifiedName(packagePath(), "New") | this = f) }
  }

  /**
   * A write to the value of Access-Control-Allow-Credentials header
   */
  class AllowCredentialsWrite extends DataFlow::ExprNode {
    DataFlow::Node base;
    GinConfig gc;

    AllowCredentialsWrite() {
      exists(Field f, Write w |
        f.hasQualifiedName(packagePath(), "Config", "AllowCredentials") and
        w.writesField(base, f, this) and
        this.getType() instanceof BoolType and
        (
          gc.getV().getBaseVariable().getDefinition().(SsaExplicitDefinition).getRhs() =
            base.asInstruction() or
          gc.getV().getAUse() = base
        )
      )
    }

    GinConfig getConfig() { result = gc }
  }

  /**
   * A write to the value of Access-Control-Allow-Origins header
   */
  class AllowOriginsWrite extends DataFlow::ExprNode {
    DataFlow::Node base;
    GinConfig gc;

    AllowOriginsWrite() {
      exists(Field f, Write w |
        f.hasQualifiedName(packagePath(), "Config", "AllowOrigins") and
        w.writesField(base, f, this) and
        this.asExpr() instanceof SliceLit and
        (
          gc.getV().getBaseVariable().getDefinition().(SsaExplicitDefinition).getRhs() =
            base.asInstruction() or
          gc.getV().getAUse() = base
        )
      )
    }

    GinConfig getConfig() { result = gc }
  }

  /**
   * A write to the value of Access-Control-Allow-Origins to "*"
   */
  class AllowAllOriginsWrite extends DataFlow::ExprNode {
    DataFlow::Node base;
    GinConfig gc;

    AllowAllOriginsWrite() {
      exists(Field f, Write w |
        f.hasQualifiedName(packagePath(), "Config", "AllowAllOrigins") and
        w.writesField(base, f, this) and
        this.getType() instanceof BoolType and
        (
          gc.getV().getBaseVariable().getDefinition().(SsaExplicitDefinition).getRhs() =
            base.asInstruction() or
          gc.getV().getAUse() = base
        )
      )
    }

    GinConfig getConfig() { result = gc }
  }

  /**
   * A variable of type Config that holds the headers to be set.
   */
  class GinConfig extends Variable {
    SsaWithFields v;

    GinConfig() {
      this = v.getBaseVariable().getSourceVariable() and
      exists(Type t | t.hasQualifiedName(packagePath(), "Config") | v.getType() = t)
    }

    SsaWithFields getV() { result = v }
  }
}
