/**
 * Instantiates the shared SSA library for JavaScript data flow.
 *
 * Refinements are value-preserving uncertain writes, so shared SSA routes flow
 * through refinements and their phi inputs. Phi definitions are retained to
 * preserve the JavaScript SSA definition-node API.
 * Synthetic reads at operation completion carry post-updates past argument
 * and right-hand-side evaluation without changing the earlier expression values.
 */
overlay[local?]
module;

private import javascript as js
private import codeql.ssa.Ssa
private import semmle.javascript.internal.BasicBlockInternal as BasicBlockInternal
private import semmle.javascript.dataflow.internal.VariableOrThis

private predicate explicitVariableRead(js::ControlFlowNode read, SsaConfig::SourceVariable v) {
  read.(js::VarUse).getVariable() = v.asLocalVariable()
  or
  read.(ThisUse).getBindingContainer() = v.asThisContainer()
}

/** Gets an operation that may update the object evaluated at `read`. */
private js::ControlFlowNode postUpdateOperation(js::ControlFlowNode read) {
  exists(js::InvokeExpr call | read = call.getAnArgument() or read = call.getCallee() |
    result = call
  )
  or
  exists(js::PropAccess access | read = access.getBase() |
    result.(js::VarDef).getTarget() = access
    or
    not exists(js::VarDef definition | definition.getTarget() = access) and
    result = access
    or
    access = any(js::CompoundAssignExpr assignment).getTarget() and
    result = access
    or
    access = any(js::UpdateExpr update).getOperand().getUnderlyingReference() and
    result = access
    or
    result.(js::MethodCallExpr).getCallee() = access
  )
  or
  result.(js::AwaitExpr).getOperand() = read
  or
  exists(js::Assignment assignment |
    assignment.getTarget() instanceof js::PropAccess and
    assignment.getRhs() = read and
    result = assignment
  )
  or
  read instanceof ImplicitThisUse and
  read instanceof js::FieldDefinition and
  result = read
}

// Continuations must not make otherwise dead variable definitions live.
bindingset[bb, i, v]
private predicate liveAfterOperation(js::Cfg::BasicBlock bb, int i, SsaConfig::SourceVariable v) {
  exists(v.asThisContainer())
  or
  exists(js::LocalVariable local |
    local = v.asLocalVariable() and
    (
      exists(int j |
        j > i and
        bb.useAt(j, local, _) and
        not exists(int k | i < k and k < j | bb.defAt(k, local, _))
      )
      or
      not exists(int k | k > i | bb.defAt(k, local, _)) and
      bb.getASuccessor().localIsLiveAtEntry(local)
    )
  )
}

module SsaConfig implements InputSig<js::Location, js::Cfg::BasicBlock> {
  class SourceVariable extends LocalVariableOrThis {
    SourceVariable() { not this.isCaptured() }
  }

  pragma[nomagic]
  private js::EntryBasicBlock getEntryBlock(js::StmtContainer container) {
    result.getContainer() = container
  }

  predicate variableWrite(js::Cfg::BasicBlock bb, int i, SourceVariable v, boolean certain) {
    bb instanceof js::ReachableBasicBlock and
    (
      certain = true and
      (
        bb.defAt(i, v.asLocalVariable(), _)
        or
        // Implicit initialization
        bb = getEntryBlock(v.getDeclaringContainer().getFunctionBoundary()) and
        i = -1
      )
      or
      // Refinements preserve the input value but introduce a new SSA definition.
      certain = false and
      any(js::SsaRefinementNode refinement).definesAt(bb, i, v.asLocalVariable())
    )
  }

  predicate variableRead(js::Cfg::BasicBlock bb, int i, SourceVariable v, boolean certain) {
    bb instanceof js::ReachableBasicBlock and
    certain = true and
    (
      explicitVariableRead(bb.getNode(i), v)
      or
      liveAfterOperation(bb, i, v) and
      exists(js::ControlFlowNode read |
        explicitVariableRead(read, v) and
        postUpdateOperation(read) = bb.getNode(i)
      )
    )
  }
}

import Make<js::Location, js::Cfg, SsaConfig>

module SsaDataflowInput implements DataFlowIntegrationInputSig {
  private import codeql.util.Boolean

  class Expr extends js::ControlFlowNode {
    Expr() {
      this = any(SsaConfig::SourceVariable v).getAUse()
      or
      exists(js::ControlFlowNode read |
        explicitVariableRead(read, _) and
        this = postUpdateOperation(read)
      )
    }

    predicate hasCfgNode(js::Cfg::BasicBlock bb, int i) { this = bb.getNode(i) }
  }

  predicate ssaDefHasSource(WriteDefinition def) {
    exists(SsaConfig::SourceVariable v, js::Cfg::BasicBlock bb, int i |
      def.definesAt(v, bb, i) and
      (
        exists(js::VarDef write |
          bb.defAt(i, v.asLocalVariable(), write) and
          write.getTarget() instanceof js::VarRef and
          exists(write.getSource())
        )
        or
        i = -1 and exists(v.asThisContainer())
      )
    )
  }

  predicate allowFlowIntoUncertainDef(UncertainWriteDefinition def) { any() }

  predicate includePhiDefsInFlowStep() { any() }

  private predicate preservesDefinition(Definition before, Definition after) {
    before = after
    or
    exists(Definition input |
      (
        uncertainWriteDefinitionInput(after, input)
        or
        phiHasInputFromBlock(after, input, _)
      ) and
      preservesDefinition(before, input)
    )
  }

  predicate postUpdateCfgNode(Expr read, js::Cfg::BasicBlock bb, int i) {
    postUpdateOperation(read) = bb.getNode(i) and
    exists(
      SsaConfig::SourceVariable v, Definition before, Definition after, js::BasicBlock readBlock,
      int readIndex
    |
      explicitVariableRead(read, v) and
      read = readBlock.getNode(readIndex) and
      ssaDefReachesRead(v, before, readBlock, readIndex) and
      SsaConfig::variableRead(bb, i, v, true) and
      ssaDefReachesRead(v, after, bb, i) and
      // A later argument may have reassigned the variable to a different object.
      preservesDefinition(before, after)
    )
  }

  cached
  Expr getARead(Definition def) {
    // Copied from implementation so we can cache it here
    exists(SsaConfig::SourceVariable v, js::BasicBlock bb, int i |
      ssaDefReachesRead(v, def, bb, i) and
      SsaConfig::variableRead(bb, i, v, true) and
      result.hasCfgNode(bb, i)
    )
  }

  class GuardValue = Boolean;

  class Guard extends js::ControlFlowNode {
    Guard() { this = any(js::ConditionGuardNode g).getTest() }

    /**
     * Holds if the evaluation of this guard to `branch` corresponds to the edge
     * from `bb1` to `bb2`.
     */
    predicate hasValueBranchEdge(js::Cfg::BasicBlock bb1, js::Cfg::BasicBlock bb2, GuardValue branch) {
      exists(js::ConditionGuardNode g |
        g.getTest() = this and
        bb1 = this.getBasicBlock() and
        bb2 = g.getBasicBlock() and
        branch = g.getOutcome()
      )
    }

    /**
     * Holds if this guard evaluating to `branch` controls the control-flow
     * branch edge from `bb1` to `bb2`. That is, following the edge from
     * `bb1` to `bb2` implies that this guard evaluated to `branch`.
     */
    predicate valueControlsBranchEdge(
      js::Cfg::BasicBlock bb1, js::Cfg::BasicBlock bb2, GuardValue branch
    ) {
      this.hasValueBranchEdge(bb1, bb2, branch)
    }
  }

  overlay[caller?]
  pragma[inline]
  predicate guardDirectlyControlsBlock(Guard guard, js::Cfg::BasicBlock bb, GuardValue branch) {
    exists(js::ConditionGuardNode g |
      g.getTest() = guard and
      g.dominates(bb) and
      branch = g.getOutcome()
    )
  }
}

import DataFlowIntegration<SsaDataflowInput>

/** Holds if `read` is an original variable or `this` read, not a continuation reference. */
predicate isExplicitRead(SsaDataflowInput::Expr read) { explicitVariableRead(read, _) }

/** Holds if `read` is a synthetic continuation at a potentially mutating operation. */
predicate isPostUpdateRead(ExprNode read) {
  not explicitVariableRead(read.getExpr(), read.getSourceVariable())
}
