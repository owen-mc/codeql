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
}
