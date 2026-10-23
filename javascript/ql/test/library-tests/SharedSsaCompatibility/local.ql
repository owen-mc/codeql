import javascript
import utils.test.InlineExpectationsTest

private DataFlow::PostUpdateNode postUpdateForSource(string value) {
  exists(Assignment assignment, PropAccess property, DataFlow::InvokeNode source |
    assignment.getTarget() = property and
    assignment.getRhs() = source.asExpr() and
    source.getCalleeName() = "SOURCE" and
    source.getArgument(0).getStringValue() = value and
    result.getPreUpdateNode() = DataFlow::valueNode(property.getBase())
  )
}

module InlineTest implements TestSig {
  string getARelevantTag() {
    result =
      [
        "localFlow", "postUpdateFlow", "noPostUpdateFlow", "noImmediatePostUpdate", "noSuperFlow",
        "noThisSelfFlow"
      ]
  }

  predicate hasActualResult(Location location, string element, string tag, string value) {
    element = "" and
    location.getFile().getBaseName() = "local.js" and
    (
      tag = "localFlow" and
      exists(DataFlow::InvokeNode source, DataFlow::InvokeNode sink |
        source.getCalleeName() = "SOURCE" and
        value = source.getArgument(0).getStringValue() and
        sink.getCalleeName() = "SINK" and
        source.getContainer() = sink.getContainer() and
        source.flowsTo(sink.getArgument(0)) and
        location = sink.getLocation()
      )
      or
      tag = "postUpdateFlow" and
      exists(DataFlow::InvokeNode sink, DataFlow::PostUpdateNode update |
        sink.getCalleeName() = "SINK" and
        update = postUpdateForSource(value) and
        update.getContainer() = sink.getContainer() and
        update.getASuccessor+() = sink.getArgument(0) and
        location = sink.getLocation()
      )
      or
      tag = "noPostUpdateFlow" and
      exists(DataFlow::InvokeNode sink, DataFlow::PostUpdateNode update |
        sink.getCalleeName() = "SINK" and
        update = postUpdateForSource(value) and
        update.getContainer() = sink.getContainer() and
        not update.getASuccessor+() = sink.getArgument(0) and
        location = sink.getLocation()
      )
      or
      tag = "noImmediatePostUpdate" and
      value = "update-immediate-predecessor" and
      exists(DataFlow::InvokeNode sink, DataFlow::PostUpdateNode update |
        sink.getCalleeName() = "SINK" and
        update = postUpdateForSource(value) and
        update.getContainer() = sink.getContainer() and
        not sink.getArgument(0).getImmediatePredecessor() = update and
        location = sink.getLocation()
      )
      or
      tag = "noSuperFlow" and
      value = "" and
      exists(SuperCall call, Function constructor |
        constructor = call.getEnclosingFunction() and
        not DataFlow::thisNode(constructor).flowsTo(DataFlow::valueNode(call.getCallee())) and
        location = call.getLocation()
      )
      or
      tag = "noThisSelfFlow" and
      value = "" and
      exists(SuperCall call, Function constructor, DataFlow::ThisNode thisNode |
        constructor = call.getEnclosingFunction() and
        thisNode = DataFlow::thisNode(constructor) and
        not thisNode.getASuccessor() = thisNode and
        location = call.getLocation()
      )
    )
  }
}

import MakeTest<InlineTest>
