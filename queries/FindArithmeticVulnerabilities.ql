/**
 * @name Tainted Integer and Divide-by-Zero Vulnerabilities
 * @description Finds potential arithmetic vulnerabilities where user-controlled data flows into sensitive operations.
 * @kind path-problem
 * @problem.severity error
 * @id java/tainted-arithmetic-vulnerabilities
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph  

/**
 * A configuration for tracking taint from remote user input to sensitive arithmetic operations.
 */
class ArithmeticTaintConfig extends TaintTracking::Configuration {
  ArithmeticTaintConfig() { this = "TaintedArithmeticVulnerability" }

  /**
   * Defines the sources of untrusted data. We consider any data that
   * originates from a remote source (network, HTTP request, etc.) as tainted.
   */
  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  /**
   * Defines the sinks, which are the sensitive operations where tainted data
   * should not arrive without sanitization.
   */
  override predicate isSink(DataFlow::Node sink) {
    // Sink 1: The divisor (second operand) of a division expression.
    exists(DivExpr div | sink.asExpr() = div.getRightOperand())
    or
    // Sink 2: An operand of a multiplication expression.
    exists(MulExpr mul | sink.asExpr() = mul.getAnOperand())
    or
    // Sink 3: An operand of an addition expression.
    exists(AddExpr add | sink.asExpr() = add.getAnOperand())
  }
}

// The main part of the query.
from ArithmeticTaintConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink, "Tainted data from $@ flows to this arithmetic operation.",
  source.getNode(), "this user-controlled source"