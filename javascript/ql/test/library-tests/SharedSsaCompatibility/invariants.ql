import javascript
import semmle.javascript.dataflow.internal.DataFlowNode
import semmle.javascript.dataflow.internal.sharedlib.Ssa as Ssa2
import Ssa2::Consistency
import Ssa2::DfConsistency

query predicate nonUniqueSsaDefinition(SsaDefinition definition, int nodes) {
  nodes = count(DataFlow::ssaDefinitionNode(definition)) and
  nodes != 1
}

query predicate nonUniqueSsaVariable(DataFlow::SsaDefinitionNode node, int variables) {
  variables = count(node.getSsaVariable()) and
  variables != 1
}

query predicate missingSsaNodeMetadata(DataFlow::Node node) {
  (
    node instanceof TSharedSsaDefNode or
    node instanceof TSharedSsaReadNode or
    node instanceof TSsaSynthReadNode or
    node instanceof TRefinementNode or
    node instanceof TLegacySsaPhiNode or
    node instanceof TCapturedVariableWriteNode or
    node instanceof TCapturedSsaInitNode or
    node instanceof TCapturedSsaCaptureNode
  ) and
  not (
    exists(node.toString()) and
    (exists(node.getBasicBlock()) or node instanceof TSharedSsaReadNode) and
    exists(node.getContainer()) and
    exists(node.getLocation()) and
    exists(node.getFile())
  )
}

query predicate orphanSsaDefinitionNode(DataFlow::Node node) {
  (
    node instanceof TSharedSsaDefNode or
    node instanceof TRefinementNode or
    node instanceof TLegacySsaPhiNode or
    node instanceof TCapturedVariableWriteNode or
    node instanceof TCapturedSsaInitNode or
    node instanceof TCapturedSsaCaptureNode
  ) and
  not node instanceof DataFlow::SsaDefinitionNode
}

query predicate ssaDefinitionHasAstNode(DataFlow::SsaDefinitionNode node, AstNode ast) {
  ast = node.getAstNode()
}

query predicate unmappedWriteDefSourceNode(Ssa2::WriteDefSourceNode node, int mapped) {
  mapped = count(DataFlow::getNodeFromSharedSsa(node)) and
  mapped != 1
}

query predicate postUpdateMustFlow(DataFlow::PostUpdateNode update, DataFlow::Node node) {
  node.getImmediatePredecessor() = update
}
