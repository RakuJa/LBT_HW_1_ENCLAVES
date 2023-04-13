open Env

type expr =
  | Nint of int
  | Nbool of bool
  | Nstring of string
  | Var of ide
  | Let of ide * expr * expr
  | SecLet of ide * expr * expr
  | Prim of ide * expr * expr
  | If of expr * expr * expr
  | Fun of ide * expr
  | Call of expr * expr
  | Enclave of ide * expr
  | Gateway of ide * expr
  | IncludeUntrusted of ide * expr
  | ExecuteUntrusted of string

type value =
  | Int of int
  | Closure of ide * expr * value env