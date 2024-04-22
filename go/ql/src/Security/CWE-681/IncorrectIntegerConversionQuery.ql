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

from
  Flow::PathNode source, Flow::PathNode sink, DataFlow::CallNode call, DataFlow::Node sinkConverted
where
  Flow::flowPath(source, sink) and
  (
    source.getState().getArchitectureBitSize() = 64
    or
    source.getState().getArchitectureBitSize() = 32 and
    not exists(Flow::PathNode source2, Flow::PathNode sink2 |
      Flow::flowPath(source2, sink2) and
      source2.getNode() = source.getNode() and
      sink2.getNode() = sink.getNode() and
      source2.getState().getArchitectureBitSize() = 64
    )
  ) and
  call.getResult(0) = source.getNode() and
  sinkConverted = sink.getNode().getASuccessor()
select sinkConverted, source, sink,
  "Incorrect conversion of " + describeBitSize2(source.getNode()) +
    " from $@ to a lower bit size type " + sinkConverted.getType().getUnderlyingType().getName() +
    " without an upper bound check.", source, call.getTarget().getQualifiedName()
