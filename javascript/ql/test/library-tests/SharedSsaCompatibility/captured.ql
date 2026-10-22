import javascript
import semmle.javascript.dataflow.internal.DataFlowNode
import utils.test.InlineExpectationsTest

module InlineTest implements TestSig {
  string getARelevantTag() { result = ["capturedWrite", "noCapturedWrite"] }

  predicate hasActualResult(Location location, string element, string tag, string value) {
    element = "" and
    exists(VarRef reference |
      reference.getFile().getBaseName() = "captured.js" and
      value = reference.getVariable().getName() and
      value = ["capturedWrite", "uncapturedWrite", "globalWrite", "capturedPattern"] and
      location = reference.getLocation() and
      (
        tag = "capturedWrite" and
        exists(DataFlow::Node node | node = TCapturedVariableWriteNode(reference))
        or
        tag = "noCapturedWrite" and
        not exists(DataFlow::Node node | node = TCapturedVariableWriteNode(reference))
      )
    )
  }
}

import MakeTest<InlineTest>
