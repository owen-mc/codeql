function refinementBarrier() {
  const refinementBarrierSource = SOURCE("refinement-barrier");
  if (!refinementBarrierSource) {
    SINK(refinementBarrierSource); // $ barrier=refinement-barrier
  }
}
