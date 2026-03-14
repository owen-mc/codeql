/**
 * @kind path-problem
 */

import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.dataflow.FlowBarrier
import utils.test.InlineFlowTest
import PathGraph

module CustomConfig implements DataFlow::ConfigSig {
  predicate isSource = DefaultFlowConfig::isSource/1;

  predicate isSink = DefaultFlowConfig::isSink/1;

  predicate isBarrier(DataFlow::Node n) { barrierNode(n, "test") }
}

import FlowTest<CustomConfig, CustomConfig>

from PathNode source, PathNode sink
where flowPath(source, sink)
select sink, source, sink, "$@", source, source.toString()
