// generated by codegen
import codeql.rust.elements
import TestUtils

from RangeExpr x, string hasLhs, string hasRhs, string isInclusive
where
  toBeTested(x) and
  not x.isUnknown() and
  (if x.hasLhs() then hasLhs = "yes" else hasLhs = "no") and
  (if x.hasRhs() then hasRhs = "yes" else hasRhs = "no") and
  if x.isInclusive() then isInclusive = "yes" else isInclusive = "no"
select x, "hasLhs:", hasLhs, "hasRhs:", hasRhs, "isInclusive:", isInclusive
