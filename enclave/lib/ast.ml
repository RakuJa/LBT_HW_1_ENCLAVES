open Env
 
type expr =
  | Nint of int
  | Nbool of bool
  | Nstring of string
  | Nunit of unit
  | Var of identifier
  | Let of identifier * expr * expr
  (* Tipes for the primitives, +, - etc*)
  | Prim of identifier * expr * expr
  | If of expr * expr * expr
  (* Lambda: parameters *)
  | Fun of identifier * expr
  | Call of expr * expr
    (* SecLet type, id, variable value, body *)
  | SecLet of identifier * expr * expr
  (* It's a list because we can separate all the expressions inside for further analysis*)
  | Enclave of identifier * expr list
  (* Type, Function name, argument_name, expr *)
  | Gateway of identifier * string * expr
  | EncEnd of expr
  | IncludeUntrusted of identifier * expr
  | ExecuteUntrusted of expr
 
(*
  A runtime value is an integer or a function closure
  Boolean are encoded as integers.
*)
type value = Int of int | String of string | Unit of unit | Closure of identifier * expr * value env
 