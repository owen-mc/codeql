/**
 * @name Uncontrolled thread resource consumption from local input source
 * @description Use user input directly to control thread sleep time could lead to performance problems
 *              or even resource exhaustion.
 * @kind path-problem
 * @id java/thread-resource-abuse
 * @problem.severity recommendation
 * @tags security
 *       external/cwe/cwe-400
 */

import java
import ThreadPauseSink
import semmle.code.java.dataflow.FlowSources
import DataFlow::PathGraph

/** The `getInitParameter` method of servlet or JSF. */
class GetInitParameter extends Method {
  GetInitParameter() {
    (
      this.getDeclaringType()
          .getASupertype*()
          .hasQualifiedName(["javax.servlet", "jakarta.servlet"],
            ["FilterConfig", "Registration", "ServletConfig", "ServletContext"]) or
      this.getDeclaringType()
          .getASupertype*()
          .hasQualifiedName(["javax.faces.context", "jakarta.faces.context"], "ExternalContext")
    ) and
    this.getName() = "getInitParameter"
  }
}

/** An access to the `getInitParameter` method. */
class GetInitParameterAccess extends MethodAccess {
  GetInitParameterAccess() { this.getMethod() instanceof GetInitParameter }
}

/* Init parameter input of a Java EE web application. */
class InitParameterInput extends LocalUserInput {
  InitParameterInput() { this.asExpr() instanceof GetInitParameterAccess }
}

private class LessThanSanitizer extends DataFlow::BarrierGuard {
  LessThanSanitizer() { this instanceof ComparisonExpr }

  override predicate checks(Expr e, boolean branch) {
    e = this.(ComparisonExpr).getLesserOperand() and
    branch = true
    or
    e = this.(ComparisonExpr).getGreaterOperand() and
    branch = false
  }
}

/** Taint configuration of uncontrolled thread resource consumption from local user input. */
class ThreadResourceAbuse extends TaintTracking::Configuration {
  ThreadResourceAbuse() { this = "ThreadResourceAbuse" }

  override predicate isSource(DataFlow::Node source) { source instanceof LocalUserInput }

  override predicate isSink(DataFlow::Node sink) { sink instanceof PauseThreadSink }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(
      Method rm, ClassInstanceExpr ce, Argument arg, Parameter p, FieldAccess fa, int i // thread.start() invokes the run() method of thread implementation
    |
      rm.hasName("run") and
      ce.getConstructedType().getSourceDeclaration() = rm.getSourceDeclaration().getDeclaringType() and
      ce.getConstructedType().getASupertype*().hasQualifiedName("java.lang", "Runnable") and
      ce.getArgument(i) = arg and
      ce.getConstructor().getParameter(i) = p and
      fa.getEnclosingCallable() = rm and
      DataFlow::localExprFlow(p.getAnAccess(), fa.getField().getAnAssignedValue()) and
      node1.asExpr() = arg and
      node2.asExpr() = fa
    )
    or
    exists(Method um, VarAccess va, FieldAccess fa, Constructor ce, AssignExpr ar |
      um.getDeclaringType()
          .getASupertype*()
          .hasQualifiedName("org.apache.commons.fileupload", "ProgressListener") and
      um.hasName("update") and
      fa.getEnclosingCallable() = um and
      ce.getDeclaringType() = um.getDeclaringType() and
      va = ce.getAParameter().getAnAccess() and
      node1.asExpr() = va and
      node2.asExpr() = fa and
      ar.getSource() = va and
      ar.getDest() = fa.getField().getAnAccess()
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(
      MethodAccess ma // Math.min(sleepTime, MAX_INTERVAL)
    |
      ma.getMethod().hasQualifiedName("java.lang", "Math", "min") and
      node.asExpr() = ma.getAnArgument()
    )
  }

  override predicate isSanitizerGuard(DataFlow::BarrierGuard guard) {
    guard instanceof LessThanSanitizer // if (sleepTime > 0 && sleepTime < 5000) { ... }
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, ThreadResourceAbuse conf
where conf.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Vulnerability of uncontrolled resource consumption due to $@.", source.getNode(),
  "local user-provided value"
