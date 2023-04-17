open Env
 
type identifier = string
type ty =
  | Nint of int
  | Nbool of bool
  | Nstring of string
  | Nunit of unit
  (* ... other possible types ... *)
  
 
type func_type =
  (* Function arguments (0..n), return type *)
  | FuncType of ty * ty
 
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
    (* EncLet type, id, variable value, body *)
  | EncLet of ty * identifier * expr * expr
 
  (* It's a list because we can separate all the expressions inside for further analysis*)
  | Enclave of identifier * expr list
  (* Type, Function name, argument_name, expr *)
  | Gateway of func_type * identifier * string * expr
  | IncludeUntrusted of identifier * expr
  | ExecuteUntrusted of expr
 
(*
  A runtime value is an integer or a function closure
  Boolean are encoded as integers.
*)
type value = Int of int | String of string | Unit of unit | Closure of identifier * expr * value env
 