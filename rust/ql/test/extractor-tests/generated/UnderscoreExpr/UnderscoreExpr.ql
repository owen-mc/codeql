// generated by codegen, do not edit
import codeql.rust.elements
import TestUtils

from UnderscoreExpr x, int getNumberOfAttrs
where
  toBeTested(x) and
  not x.isUnknown() and
  getNumberOfAttrs = x.getNumberOfAttrs()
select x, "getNumberOfAttrs:", getNumberOfAttrs
