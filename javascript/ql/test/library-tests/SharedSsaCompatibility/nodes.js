function ordinaryPhiNodes(condition, otherCondition) {
  let value;
  if (condition) {
    value = "first";
  } else {
    value = "second";
  }
  if (otherCondition) {
    CHECK(value); // $ uniquePhiDefinition phiReachesCheck globalPhiReachesCheck MISSING: phiNodeMetadata
  } else {
    use(value);
  }
}

function refinedPhiNodes(value, condition) {
  if (value) {
    value = "safe";
  }
  if (condition) {
    CHECK(value); // $ phiNodeMetadata phiReachesCheck globalPhiReachesCheck MISSING: uniquePhiDefinition
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
    CHECK(value); // $ uniquePhiDefinition MISSING: phiNodeMetadata phiReachesCheck globalPhiReachesCheck
  } else {
    use(value);
  }
}
