import javascript
import utils.test.InlineExpectationsTest

module RefinementConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.(DataFlow::InvokeNode).getCalleeName() = "SOURCE"
    or
    source = any(DataFlow::InvokeNode call | call.getCalleeName() = "READ_SOURCE").getArgument(0)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::InvokeNode call |
      call.getCalleeName() = ["SINK", "BLOCKED_SINK"] and
      sink = call.getArgument(0)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof DataFlow::VarAccessBarrier
    or
    node = DataFlow::MakeBarrierGuard<SimpleBarrierGuard>::getABarrierNode()
    or
    node = any(DataFlow::InvokeNode call | call.getCalleeName() = "BLOCKED_SINK").getArgument(0)
  }
}

module RefinementFlow = DataFlow::Global<RefinementConfig>;

module RefinementTaint = TaintTracking::Global<RefinementConfig>;

class SimpleBarrierGuard extends DataFlow::InvokeNode {
  SimpleBarrierGuard() { this.getCalleeName() = "BARRIER" }

  predicate blocksExpr(boolean outcome, Expr expr) {
    outcome = true and
    expr = this.getArgument(0).asExpr()
  }
}

private predicate localStepWithoutRefinement(DataFlow::Node pred, DataFlow::Node succ) {
  DataFlow::localFlowStep(pred, succ) and
  not succ.(DataFlow::SsaDefinitionNode).getSsaVariable().getDefinition() instanceof
    SsaRefinementNode
}

module InlineTest implements TestSig {
  string getARelevantTag() {
    result =
      [
        "barrier", "refinementFlow", "noRefinementFlow", "refinementTaint", "noRefinementTaint",
        "localRefinementFlow", "noRefinementBypass"
      ]
  }

  predicate hasActualResult(Location location, string element, string tag, string value) {
    element = "" and
    location.getFile().getBaseName() = ["refinement.js", "namespace.ts"] and
    exists(
      DataFlow::InvokeNode sourceCall, DataFlow::Node source, DataFlow::InvokeNode sink,
      VarRef sinkArgument
    |
      (
        sourceCall.getCalleeName() = "SOURCE" and
        source = sourceCall and
        value = sourceCall.getArgument(0).getStringValue()
        or
        sourceCall.getCalleeName() = "READ_SOURCE" and
        source = sourceCall.getArgument(0) and
        value = sourceCall.getArgument(1).getStringValue()
      ) and
      sink.getCalleeName() = ["SINK", "BLOCKED_SINK"] and
      source.getContainer() = sink.getContainer() and
      sink.getArgument(0) = DataFlow::valueNode(sinkArgument) and
      location = sink.getLocation() and
      (
        tag = "refinementFlow" and RefinementFlow::flow(source, sink.getArgument(0))
        or
        tag = "noRefinementFlow" and not RefinementFlow::flow(source, sink.getArgument(0))
        or
        tag = "refinementTaint" and RefinementTaint::flow(source, sink.getArgument(0))
        or
        tag = "noRefinementTaint" and not RefinementTaint::flow(source, sink.getArgument(0))
        or
        tag = "localRefinementFlow" and source.getASuccessor*() = sink.getArgument(0)
        or
        tag = "noRefinementBypass" and
        source.getASuccessor*() = sink.getArgument(0) and
        not localStepWithoutRefinement*(source, sink.getArgument(0))
        or
        tag = "barrier" and
        DataFlow::ssaDefinitionNode(sinkArgument.(VarUse).getSsaVariable().getDefinition())
          instanceof DataFlow::VarAccessBarrier
      )
    )
  }
}

import MakeTest<InlineTest>
