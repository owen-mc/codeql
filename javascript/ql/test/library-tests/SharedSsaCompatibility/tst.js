function compatibilityPhi() {
  let compatibilityPhiSource = SOURCE();
  if (false) {
    compatibilityPhiSource = "unreachable";
  }
  SINK(compatibilityPhiSource); // $ source=compatibility-phi flow=compatibility-phi
}
