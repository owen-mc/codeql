function refinementBarrier() {
  const refinementBarrierSource = SOURCE("refinement-barrier");
  if (!refinementBarrierSource) {
    SINK(refinementBarrierSource); // $ barrier=refinement-barrier noRefinementFlow=refinement-barrier noRefinementTaint=refinement-barrier localRefinementFlow=refinement-barrier noRefinementBypass=refinement-barrier
  }
}

function phiReadInsideRefinement(condition) {
  const phiReadSource = SOURCE("refined-phi-read");
  if (phiReadSource) {
    if (condition) {
      if (!BARRIER(phiReadSource)) return;
    } else {
      if (!BARRIER(phiReadSource)) return;
    }
    SINK(phiReadSource); // $ noRefinementFlow=refined-phi-read noRefinementTaint=refined-phi-read localRefinementFlow=refined-phi-read noRefinementBypass=refined-phi-read
  }
}

function refinementFollowedByPhi(condition) {
  let refinementPhiSource = SOURCE("refinement-phi");
  if (!refinementPhiSource) {
    if (condition) {
      refinementPhiSource = "safe";
    }
    SINK(refinementPhiSource); // $ noRefinementFlow=refinement-phi noRefinementTaint=refinement-phi localRefinementFlow=refinement-phi noRefinementBypass=refinement-phi
  }
}

function equalityCompatibilityPhi() {
  const value = SOURCE("equality-phi");
  if (value === "a" || value === "b") {
    SINK(value); // $ refinementFlow=equality-phi noRefinementTaint=equality-phi localRefinementFlow=equality-phi noRefinementBypass=equality-phi
  }
}

function nestedCompatibilityPhi(condition) {
  const value = SOURCE("nested-equality-phi");
  if (value === "a" || value === "b") {
    if (condition) {
      use(value);
    } else {
      use(value);
    }
    SINK(value); // $ refinementFlow=nested-equality-phi noRefinementTaint=nested-equality-phi localRefinementFlow=nested-equality-phi noRefinementBypass=nested-equality-phi
  }
}

function unguardedWriteAfterTruthyTest(value) {
  if (value) {
    value = SOURCE("unguarded-shared-phi");
  }
  SINK(value); // $ refinementFlow=unguarded-shared-phi refinementTaint=unguarded-shared-phi localRefinementFlow=unguarded-shared-phi
}

function unguardedWriteInsideFalseRefinement(value, condition) {
  if (!value) {
    if (condition) {
      value = SOURCE("nested-shared-phi");
    }
    SINK(value); // $ refinementFlow=nested-shared-phi refinementTaint=nested-shared-phi localRefinementFlow=nested-shared-phi
  }
}

function transitiveSharedPhis(value, condition) {
  if (value) {
    value = SOURCE("first-shared-phi");
  }
  if (condition) {
    value = SOURCE("second-shared-phi");
  }
  SINK(value); // $ refinementFlow=first-shared-phi refinementTaint=first-shared-phi localRefinementFlow=first-shared-phi refinementFlow=second-shared-phi refinementTaint=second-shared-phi localRefinementFlow=second-shared-phi
}

function phiReadAfterSharedPhi(value, condition) {
  if (value) {
    value = SOURCE("shared-phi-then-read");
  }
  if (condition) {
    use(value);
  } else {
    use(value);
  }
  SINK(value); // $ refinementFlow=shared-phi-then-read refinementTaint=shared-phi-then-read localRefinementFlow=shared-phi-then-read
}

function filteredPhiInputWithReplacement(condition, otherCondition) {
  let value = SOURCE("filtered-phi-input");
  if (!value) {
    if (condition) {
      value = SOURCE("replacement-phi-input");
    }
    if (otherCondition) {
      SINK(value); // $ noRefinementFlow=filtered-phi-input noRefinementTaint=filtered-phi-input localRefinementFlow=filtered-phi-input noRefinementBypass=filtered-phi-input refinementFlow=replacement-phi-input refinementTaint=replacement-phi-input localRefinementFlow=replacement-phi-input
    } else {
      SINK(value); // $ noRefinementFlow=filtered-phi-input noRefinementTaint=filtered-phi-input localRefinementFlow=filtered-phi-input noRefinementBypass=filtered-phi-input refinementFlow=replacement-phi-input refinementTaint=replacement-phi-input localRefinementFlow=replacement-phi-input
    }
  }

  function emptyRefinementBranches() {
    const value = SOURCE("empty-refinement-branches");
    if (value) {}
    SINK(value); // $ refinementFlow=empty-refinement-branches refinementTaint=empty-refinement-branches localRefinementFlow=empty-refinement-branches noRefinementBypass=empty-refinement-branches
  }

  function nestedSingleReadPhis(firstCondition, secondCondition) {
    let value;
    if (firstCondition) {
      if (secondCondition) {
        value = SOURCE("nested-single-read-phis");
      } else {
        value = "safe";
      }
      otherOperation();
    } else {
      value = "safe";
    }
    SINK(value); // $ refinementFlow=nested-single-read-phis refinementTaint=nested-single-read-phis localRefinementFlow=nested-single-read-phis
  }

  function nestedMultipleReadPhis(firstCondition, secondCondition, thirdCondition) {
    let value;
    if (firstCondition) {
      if (secondCondition) {
        value = SOURCE("nested-multiple-read-phis");
      } else {
        value = "safe";
      }
      otherOperation();
    } else {
      value = "safe";
    }
    if (thirdCondition) {
      SINK(value); // $ refinementFlow=nested-multiple-read-phis refinementTaint=nested-multiple-read-phis localRefinementFlow=nested-multiple-read-phis
    } else {
      use(value);
    }
  }

  function refinementAfterGuardedJoin(condition) {
    const value = SOURCE("refinement-after-guarded-join");
    if (value) {
      if (condition) {
        if (!BARRIER(value)) return;
      } else {
        if (!BARRIER(value)) return;
      }
      if (typeof value === "object") {
        SINK(value); // $ localRefinementFlow=refinement-after-guarded-join noRefinementBypass=refinement-after-guarded-join noRefinementFlow=refinement-after-guarded-join noRefinementTaint=refinement-after-guarded-join
      }
    }
  }

  function conditionalReadInsideFalsyRefinement(condition) {
    const value = SOURCE("conditional-read-in-refinement");
    if (!value) {
      if (condition) {
        use(value);
      }
      SINK(value); // $ barrier=conditional-read-in-refinement noRefinementTaint=conditional-read-in-refinement localRefinementFlow=conditional-read-in-refinement noRefinementFlow=conditional-read-in-refinement noRefinementBypass=conditional-read-in-refinement
    }
  }

  function independentPhiInputRefinements(condition, otherCondition) {
    let value = SOURCE("independent-phi-inputs");
    if (condition) {
    } else if (value) {
      value = "safe";
    }
    if (otherCondition) {
      SINK(value); // $ localRefinementFlow=independent-phi-inputs refinementFlow=independent-phi-inputs refinementTaint=independent-phi-inputs
    } else {
      use(value);
    }
  }

  function occurrenceSpecificBarrier() {
    const value = SOURCE("occurrence-barrier");
    BLOCKED_SINK(value); // $ noRefinementFlow=occurrence-barrier noRefinementTaint=occurrence-barrier localRefinementFlow=occurrence-barrier
    SINK(value); // $ localRefinementFlow=occurrence-barrier refinementFlow=occurrence-barrier refinementTaint=occurrence-barrier
  }

  function guardedCallResultDoesNotValidateArgument() {
    const value = SOURCE("guarded-call-result");
    if (!BARRIER(transform(value))) return;
    SINK(value); // $ localRefinementFlow=guarded-call-result refinementFlow=guarded-call-result refinementTaint=guarded-call-result
  }

  function occurrenceSpecificBarriersBeforeJoin(condition) {
    const value = SOURCE("occurrence-barriers-before-join");
    if (condition) {
      BLOCKED_SINK(value); // $ noRefinementFlow=occurrence-barriers-before-join noRefinementTaint=occurrence-barriers-before-join localRefinementFlow=occurrence-barriers-before-join
    } else {
      BLOCKED_SINK(value); // $ noRefinementFlow=occurrence-barriers-before-join noRefinementTaint=occurrence-barriers-before-join localRefinementFlow=occurrence-barriers-before-join
    }
    SINK(value); // $ refinementFlow=occurrence-barriers-before-join refinementTaint=occurrence-barriers-before-join localRefinementFlow=occurrence-barriers-before-join
  }

  function readOccurrenceSourceDoesNotContaminateVariable() {
    const value = "safe";
    READ_SOURCE(value, "read-occurrence-source");
    SINK(value); // $ noRefinementFlow=read-occurrence-source noRefinementTaint=read-occurrence-source
  }

  function indirectBarrierGuardWithReadBeforeJoin() {
    let value = SOURCE("indirect-barrier-read-join");
    const ok = BARRIER(value);
    if (ok) {
      use(value);
    } else {
      value = "safe";
    }
    SINK(value); // $ localRefinementFlow=indirect-barrier-read-join noRefinementFlow=indirect-barrier-read-join noRefinementTaint=indirect-barrier-read-join
  }

  function indirectBarrierGuardEmptyBranchBeforeJoin() {
    let value = SOURCE("indirect-barrier-empty-join");
    const ok = BARRIER(value);
    if (ok) {
    } else {
      value = "safe";
    }
    SINK(value); // $ localRefinementFlow=indirect-barrier-empty-join noRefinementFlow=indirect-barrier-empty-join noRefinementTaint=indirect-barrier-empty-join
  }

  function indirectBarrierGuardAfterRefinementBeforeJoin() {
    let value = SOURCE("indirect-barrier-after-refinement-join");
    const ok = BARRIER(value);
    if (typeof value === "object") {
      if (ok) {
      } else {
        value = "safe";
      }
      SINK(value); // $ localRefinementFlow=indirect-barrier-after-refinement-join noRefinementBypass=indirect-barrier-after-refinement-join noRefinementFlow=indirect-barrier-after-refinement-join noRefinementTaint=indirect-barrier-after-refinement-join
    }
  }

  function barrierGuardInsideWithStatement(scopeObject) {
    let value = SOURCE("barrier-in-with");
    with (scopeObject) {
      if (BARRIER(value)) {
        use(value);
      } else {
        value = "safe";
      }
    }
    SINK(value); // $ localRefinementFlow=barrier-in-with noRefinementFlow=barrier-in-with noRefinementTaint=barrier-in-with
  }

  class SharedSsaThisTests {
    guardedThisMethod(condition) {
      if (condition) {
        if (!BARRIER(this)) return;
      } else {
        if (!BARRIER(this)) return;
      }
      SINK(this); // $ localRefinementFlow=this-guard noRefinementFlow=this-guard noRefinementTaint=this-guard
    }

    occurrenceBarrierThisMethod() {
      this.property = SOURCE("this-occurrence-barrier");
      BLOCKED_SINK(this.property); // $ noRefinementFlow=this-occurrence-barrier noRefinementTaint=this-occurrence-barrier
      BLOCKED_SINK(this); // $ noRefinementFlow=this-occurrence-barrier noRefinementTaint=this-occurrence-barrier
      SINK(this.property); // $ refinementFlow=this-occurrence-barrier refinementTaint=this-occurrence-barrier
    }
  }
}
