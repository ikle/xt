# Table-based Filter

## Basic provisions

1. The table consists of a set of chains: root chains and user chains.
2. The chain consists of a sequence of rules and a default policy.
3. A rule consists of a set of match checks, a set of watchers, and a target.
4. Each rule is limited to a specific domain.
5. The message that reaches the rule is matched against all patterns in
   the rule.
6. If all checks are successful, then all rule watchers are notified and
   the target is executed.
7. The target is either the verdict, the user chain name, or the name of
   the target implemented by the plug-in module.

## Directed Graph View

A table can be thought of as a directed graph, where

*  each chain is a vertex;
*  the set of targets pointing to the user's chain are edges;
*  imaginary root vertex "kernel" with edes to the vertexes of root chains.

## Constrains

1. Loops are not allowed in the table.
2. Verdict is one of the following values: ACCEPT, DROP, CONTINUE, or RETURN.
3. For root chains, only ACCEPT and DROP verdicts are allowed as the default
   policy. If the value is not explicitly specified, then ACCEPT is assumed.
4. For user chains, only ACCEPT, DROP and RETURN are allowed as the default
   policy. If the value is not explicitly specified, then RETURN is assumed.
5. If the target of the rule is not specified, then CONTINUE is assumed.
6. The target implemented by the plug-in module must return a verdict.

