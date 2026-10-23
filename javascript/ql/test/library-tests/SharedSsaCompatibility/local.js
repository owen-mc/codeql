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

function assignmentUpdateCompletion(value) {
  value.property = SOURCE("store-completion", SINK(value)); // $ MISSING: noPostUpdateFlow=store-completion noGlobalPostUpdateFlow=store-completion SPURIOUS: postUpdateFlow=store-completion globalPostUpdateFlow=store-completion
  SINK(value); // $ postUpdateFlow=store-completion globalPostUpdateFlow=store-completion
}

function callUpdateCompletion(value) {
  UPDATE("call-completion", value, SINK(value)); // $ MISSING: noPostUpdateFlow=call-completion noGlobalPostUpdateFlow=call-completion SPURIOUS: postUpdateFlow=call-completion globalPostUpdateFlow=call-completion
  SINK(value); // $ postUpdateFlow=call-completion globalPostUpdateFlow=call-completion
}

function nestedCallUpdateCompletion(value) {
  use(UPDATE("nested-call-completion", value), SINK(value)); // $ postUpdateFlow=nested-call-completion globalPostUpdateFlow=nested-call-completion
}

function overwrittenCallArgument(value) {
  UPDATE("overwritten-call-argument", value, value = {});
  SINK(value); // $ noPostUpdateFlow=overwritten-call-argument noGlobalPostUpdateFlow=overwritten-call-argument
}

function loopUpdateCompletion(value) {
  while (condition()) {
    SINK(value); // $ postUpdateFlow=loop-completion globalPostUpdateFlow=loop-completion
    UPDATE("loop-completion", value);
    SINK(value); // $ postUpdateFlow=loop-completion globalPostUpdateFlow=loop-completion
  }
}

function reflectiveReadInference() {
  const value = () => 42;
  CHECK_TYPE(value); // $ noReflectiveValue
  with ({}) {
    CHECK_TYPE(value); // $ reflectiveValue
  }
  CHECK_TYPE(value); // $ noReflectiveValue
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

function parameterReadBeforeDeclaration(first = second, second = SOURCE("later-parameter")) {
  SINK(first);
  SINK(second); // $ localFlow=later-parameter
}

function unreachableLocalSsaCode() {
  const liveBeforeReturn = "safe";
  return liveBeforeReturn;
  const deadLocal = "dead";
  use(deadLocal);
  use(liveBeforeReturn);
}

class SharedSsaBase {}

class SharedSsaDerived extends SharedSsaBase {
  field = this.condition ? 1 : 2;

  constructor(condition) {
    if (condition) {
      super(); // $ noSuperFlow noThisSelfFlow
    } else {
      super(); // $ noSuperFlow noThisSelfFlow
    }
    use(this);
  }
}
