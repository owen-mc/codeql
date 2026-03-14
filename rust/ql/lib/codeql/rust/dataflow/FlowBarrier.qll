/**
 * Provides classes and predicates for defining barriers and barrier guards.
 *
 * Flow sinks defined here feed into data flow configurations as follows:
 *
 * ```text
 * data from *.model.yml | QL extensions of FlowSink::Range
 *  v                       v
 * FlowSink (associated with a models-as-data kind string)
 *  v
 * sinkNode predicate | other QL defined sinks, for example using concepts
 *  v                    v
 * various Sink classes for specific data flow configurations <- extending QuerySink
 * ```
 *
 * New sinks should be defined using models-as-data, QL extensions of
 * `FlowSink::Range`, or concepts. Data flow configurations should use the
 * `sinkNode` predicate and/or concepts to define their sinks.
 */

private import rust
private import internal.FlowSummaryImpl as Impl
private import internal.DataFlowImpl as DataFlowImpl

// import all instances below
private module Barriers {
  private import codeql.rust.Frameworks
  private import codeql.rust.dataflow.internal.ModelsAsData
}

/** Provides the `Range` class used to define the extent of `FlowBarrier`. */
module FlowBarrier {
  /** A flow sink. */
  abstract class Range extends Impl::Public::BarrierElement {
    bindingset[this]
    Range() { any() }

    override predicate isBarrier(
      string output, string kind, Impl::Public::Provenance provenance, string model
    ) {
      this.isBarrier(output, kind) and provenance = "manual" and model = ""
    }

    /**
     * Holds is this element is a flow barrier of kind `kind`, where data
     * flows out as described by `output`.
     */
    predicate isBarrier(string output, string kind) { none() }
  }
}

final class FlowBarrier = FlowBarrier::Range;

predicate barrierNode = DataFlowImpl::barrierNode/2;
