/**
 * @name Incorrect conversion between integer types
 * @description Converting the result of `strconv.Atoi`, `strconv.ParseInt`,
 *              and `strconv.ParseUint` to integer types of smaller bit size
 *              can produce unexpected values.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.1
 * @id go/incorrect-integer-conversion
 * @tags security
 *       external/cwe/cwe-190
 *       external/cwe/cwe-681
 * @precision very-high
 */

import go
import semmle.go.security.IncorrectIntegerConversionLib
import Flow::PathGraph

/**
 * Do not show this path because there is another path with the same source and
 * sink that should be shown instead.
 */
pragma[inline]
predicate shouldHidePath(Flow::PathNode source, Flow::PathNode sink) {
  exists(Flow::PathNode source2, Flow::PathNode sink2 |
    Flow::flowPath(source2, sink2) and
    source2.getNode() = source.getNode() and
    sink2.getNode() = sink.getNode() and
    (
      // If there are alerts for 64-bit and 32-bit architectures, only show the
      // 64-bit alert.
      source.getState().getArchitectureBitSize() = 32 and
      source2.getState().getArchitectureBitSize() = 64
      or
      // If there are multiple paths between the same source and sink and
      // architecture bit size but where the flow state has different bit sizes
      // when it gets to the sink, show the one with the highest bit size.
      sink2.getState().getArchitectureBitSize() = sink.getState().getArchitectureBitSize() and
      sink2.getState().getBitSize() > sink.getState().getBitSize()
    )
  )
}

from
  Flow::PathNode source, Flow::PathNode sink, DataFlow::CallNode call, DataFlow::Node sinkConverted
where
  Flow::flowPath(source, sink) and
  not shouldHidePath(source, sink) and
  call.getResult(0) = source.getNode() and
  sinkConverted = sink.getNode().getASuccessor()
select sinkConverted, source, sink,
  "Incorrect conversion of " + describeBitSize2(source.getNode()) +
    " from $@ to a lower bit size type " + sinkConverted.getType().getUnderlyingType().getName() +
    " without an upper bound check (source state: " + source.getState() + ", sink state: " +
    sink.getState() + ").", source, call.getTarget().getQualifiedName()
