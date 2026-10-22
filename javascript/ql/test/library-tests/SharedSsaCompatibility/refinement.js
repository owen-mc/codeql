function refinementBarrier() {
  const refinementBarrierSource = SOURCE("refinement-barrier");
  if (!refinementBarrierSource) {
    SINK(refinementBarrierSource); // $ barrier=refinement-barrier noRefinementFlow=refinement-barrier localRefinementFlow=refinement-barrier noRefinementBypass=refinement-barrier
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
    SINK(phiReadSource); // $ noRefinementFlow=refined-phi-read localRefinementFlow=refined-phi-read noRefinementBypass=refined-phi-read
  }
}

function refinementFollowedByPhi(condition) {
  let refinementPhiSource = SOURCE("refinement-phi");
  if (!refinementPhiSource) {
    if (condition) {
      refinementPhiSource = "safe";
    }
    SINK(refinementPhiSource); // $ noRefinementFlow=refinement-phi localRefinementFlow=refinement-phi noRefinementBypass=refinement-phi
  }
}

function equalityCompatibilityPhi() {
  const value = SOURCE("equality-phi");
  if (value === "a" || value === "b") {
    SINK(value); // $ refinementFlow=equality-phi localRefinementFlow=equality-phi noRefinementBypass=equality-phi
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
    SINK(value); // $ refinementFlow=nested-equality-phi localRefinementFlow=nested-equality-phi noRefinementBypass=nested-equality-phi
  }
}
