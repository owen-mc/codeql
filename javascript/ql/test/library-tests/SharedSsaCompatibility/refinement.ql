import javascript
import utils.test.InlineExpectationsTest

module RefinementConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.(DataFlow::InvokeNode).getCalleeName() = "SOURCE"
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::InvokeNode call |
      call.getCalleeName() = "SINK" and
      sink = call.getArgument(0)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof DataFlow::VarAccessBarrier
    or
    node = DataFlow::MakeBarrierGuard<SimpleBarrierGuard>::getABarrierNode()
  }
}

module RefinementFlow = DataFlow::Global<RefinementConfig>;

class SimpleBarrierGuard extends DataFlow::InvokeNode {
  SimpleBarrierGuard() { this.getCalleeName() = "BARRIER" }

  predicate blocksExpr(boolean outcome, Expr expr) {
    outcome = true and
    expr = this.getArgument(0).asExpr()
  }
}

module InlineTest implements TestSig {
  string getARelevantTag() { result = ["barrier", "refinementFlow"] }

  predicate hasActualResult(Location location, string element, string tag, string value) {
    element = "" and
    value = "refinement-barrier" and
    exists(DataFlow::InvokeNode source, DataFlow::InvokeNode sink, VarRef sinkArgument |
      source.getCalleeName() = "SOURCE" and
      source.getArgument(0).getStringValue() = value and
      sink.getCalleeName() = "SINK" and
      sink.getArgument(0) = DataFlow::valueNode(sinkArgument) and
      sinkArgument.getVariable().getName() = "refinementBarrierSource" and
      location = sink.getLocation() and
      (
        tag = "refinementFlow" and RefinementFlow::flow(source, sink.getArgument(0))
        or
        tag = "barrier" and
        exists(SsaRefinementNode refinement |
          refinement.getSourceVariable().getName() = "refinementBarrierSource" and
          DataFlow::ssaDefinitionNode(refinement) instanceof DataFlow::VarAccessBarrier
        )
      )
    )
  }
}

import MakeTest<InlineTest>
