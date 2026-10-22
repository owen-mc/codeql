function refinementBarrier() {
  const refinementBarrierSource = SOURCE("refinement-barrier");
  if (!refinementBarrierSource) {
    SINK(refinementBarrierSource); // $ barrier=refinement-barrier noRefinementFlow=refinement-barrier
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
    SINK(phiReadSource); // $ noRefinementFlow=refined-phi-read
  }
}

function refinementFollowedByPhi(condition) {
  let refinementPhiSource = SOURCE("refinement-phi");
  if (!refinementPhiSource) {
    if (condition) {
      refinementPhiSource = "safe";
    }
    SINK(refinementPhiSource); // $ noRefinementFlow=refinement-phi
  }
}
