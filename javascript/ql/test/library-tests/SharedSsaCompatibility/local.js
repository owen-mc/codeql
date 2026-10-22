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

class SharedSsaBase {}

class SharedSsaDerived extends SharedSsaBase {
  constructor() {
    super(); // $ noSuperFlow noThisSelfFlow
  }
}
