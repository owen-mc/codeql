function ordinaryPhiLocalFlow(condition, otherCondition) {
  let value;
  if (condition) {
    value = SOURCE("ordinary-phi");
  } else {
    value = {};
  }
  if (otherCondition) {
    SINK(value); // $ localFlow=ordinary-phi
  } else {
    use(value);
  }
}

function postUpdateOrdering(value) {
  SINK(value); // $ noPostUpdateFlow=post-update
  value.property = SOURCE("post-update");
  SINK(value); // $ postUpdateFlow=post-update
}

function nestedRefinementPostUpdate(value) {
  if (value) {
    if (typeof value === "object") {
      value.property = SOURCE("nested-post-update");
      SINK(value); // $ postUpdateFlow=nested-post-update
    }
  }
}

function refinedPostUpdateReads(value) {
  if (value) {
    SINK(value); // $ noPostUpdateFlow=refined-post-update
    value.property = SOURCE("refined-post-update");
    use(value);
    SINK(value); // $ postUpdateFlow=refined-post-update
  }
}

function compatibilityPhiPostUpdateReads(value) {
  if (typeof value === "object" || typeof value === "function") {
    SINK(value); // $ noPostUpdateFlow=compatibility-phi-post-update
    value.property = SOURCE("compatibility-phi-post-update");
    use(value);
    SINK(value); // $ postUpdateFlow=compatibility-phi-post-update
  }
}

function postUpdateBeforeNestedRefinement(value) {
  if (value) {
    value.property = SOURCE("update-before-refinement");
    if (typeof value === "object") {
      SINK(value); // $ postUpdateFlow=update-before-refinement
    }
  }
}

function postUpdateBeforeCompatibilityPhi(value) {
  if (value) {
    value.property = SOURCE("update-before-phi");
    use(value);
  }
  SINK(value); // $ postUpdateFlow=update-before-phi
}

function postUpdateImmediatePredecessor(value) {
  value.property = SOURCE("update-immediate-predecessor");
  SINK(value); // $ postUpdateFlow=update-immediate-predecessor noImmediatePostUpdate=update-immediate-predecessor
}

function capturedRefinementLocalFlow() {
  const value = SOURCE("captured-refinement");
  function capture() {
    use(value);
  }
  if (value) {
    if (typeof value === "object") {
      SINK(value); // $ localFlow=captured-refinement
    }
  }
}

class SharedSsaBase {}

class SharedSsaDerived extends SharedSsaBase {
  constructor() {
    super(); // $ noSuperFlow noThisSelfFlow
  }
}
