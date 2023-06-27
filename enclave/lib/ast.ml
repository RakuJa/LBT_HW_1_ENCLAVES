open Env

type expr =
  | CstI of int * sec_level
  | CstB of bool * sec_level
  | Var of ide
  | Let of ide * expr * expr
  | Prim of ide * expr * expr
  | If of expr * expr * expr
  (* Lambda: parameters, body and permission domain *)
  | Fun of ide * expr 
  | Call of expr * expr
  (* Enclave keywords *)
  | EnCall of ide * ide * expr (* How to call an enclave: EnCall nameEnclave gatewayName gatewayParams *)
  | Enclave of ide * expr * expr (* identifier, enclave Body, nextAstExpr*)
  | SecLet of ide * expr * expr (* Used for let secret*)
  | Gateway of ide * expr * expr (* Used for let gateway*)
  | EndEnclave
  (* Include keywords *)
  | IncludeUntrusted of expr * expr (* It's include AND execute at the same time, it does not need an identifier*)
  | EndUntrusted
  (*| Declassify operator for taint *)
  | Declassify of expr
(*
  A runtime value is an integer or a function closure
  Boolean are encoded as integers.
*)

type value = 
  | Int of int * sec_level
  | Closure of ide * expr * value env 
  | Renclave of value enclave 
  | EnClosure of ide * expr * value env * value env * value env
  | UntrustedEnv of value env

