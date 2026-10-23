function ordinaryPhiNodes(condition, otherCondition) {
  let value;
  if (condition) {
    value = "first";
  } else {
    value = "second";
  }
  if (otherCondition) {
    CHECK(value); // $ uniquePhiDefinition phiNodeMetadata phiReachesCheck globalPhiReachesCheck
  } else {
    use(value);
  }
}

function refinedPhiNodes(value, condition) {
  if (value) {
    value = "safe";
  }
  if (condition) {
    CHECK(value); // $ uniquePhiDefinition phiNodeMetadata phiReachesCheck globalPhiReachesCheck
  } else {
    use(value);
  }
}

function nestedPhiNodes(firstCondition, secondCondition, thirdCondition) {
  let value;
  if (firstCondition) {
    if (secondCondition) {
      value = "first";
    } else {
      value = "second";
    }
    otherOperation();
  } else {
    value = "third";
  }
  if (thirdCondition) {
    CHECK(value); // $ uniquePhiDefinition phiNodeMetadata phiReachesCheck globalPhiReachesCheck
  } else {
    use(value);
  }
}

function capturedPhiNodes(condition, otherCondition) {
  let value;
  if (condition) {
    value = "first";
  } else {
    value = "second";
  }
  function capture() {
    return value;
  }
  capture();
  if (otherCondition) {
    CHECK(value); // $ uniquePhiDefinition phiNodeMetadata phiReachesCheck MISSING: globalPhiReachesCheck
  } else {
    use(value);
  }
}
