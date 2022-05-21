# Final Year Project Tracker #

## TO FIX ##

### Change ###

```.type Code <: symbol
.type Statement <: symbol
.type Opcode <: symbol
.type Value <: symbol



/* Instructions for Andre
Start with the following schema ...
Import the facts from your Python application
*/

Statement_Pushes(statement: Statement, n: number)
Statement_Pops(statement: Statement, n: number)
Statement_Opcode(statement: Statement, opcode: Opcode)
Statement_Code(statement: Statement, code: Code)
Statement_Next(statement: Statement, statement2: Statement)
Statement_Metadata(statement: Statement, metadata: symbol)

/*
Statement_Pushes(address, 1).
Statement_Pushes(address, 1).
Statement_Next("address", "address2").

<address> :  LOAD_FAST ...
<address2> : LOAD_CONST ...
*/

/* Taken from gigahorse-toolchain/logic/local.dl */
```
## TODOs ##

* ### __Goal 1__ ###

- [x] Use md5 .hexdigest for location of address.
- [x] Implement Stack in Bytecode Disassembler.
- [x] Compute StatementStackDelta(stmt, delta)
- [x] Compute StatementPopDelta(stmt, delta)

* ### __Goal 2__ ###

- [x] Compute something like Statement_Uses and Statement_Defines for each statement, locally (within the same basic block)

* ### __Goal 3__ ###

- [ ] Compute something like Statement_Uses and Statement_Defines for each statement, globally (within the same function) */

* ### __Goal 4__ ###

- [ ] Call graph analysis

* ### __Goal 5__ ###

- [ ] Intra-procedural data flow analysis

------------------------------------
.decl Statement_Uses_Local(stmt, identifier, pos)

.decl BlockInputContents(block, index, stmt)
// block reads the output of stmt. This resides at stack location (index) *before* executing the block

.decl BlockOutputContents(block, index, stmt)
// block writes the output of stmt. This resides at stack location (index) *after* executing the block

BlockInputContents(callee, index, stmt) :-
  BlockOutputContents(caller, index, stmt),
  BlockEdge(caller, callee).

.decl BlockEdge(caller: Block, ca

-------------------------------------------------
BlockOutputContents(block, index + stackDelta, stmt) :-
  BlockInputContents(block, index, stmt),
  BlockStackDelta(block, stackDelta),
  BlockPopDelta(block, popDelta),
  index > popDelta.



statement_block(a, b) :- statement_uses_local(a,b, _).

statement_block(a, b) :- 
  statement_uses_local(a,b, c),
  !funky(c).

statement_block(a,b) :-
   statement_uses_local(_, _, c),
   statement_uses_local(a, _, c),
   statement_uses_local(_, b, c).