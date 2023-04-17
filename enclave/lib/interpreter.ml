open Ast
open Env

let rec eval (e : expr) (env : value env) : value =
  match e with
  | Nint i -> Int i
  | Nbool b -> Int (if b then 1 else 0)
  | Nstring s -> String s
  | Nunit u -> Unit u
  | Var x -> lookup env x
  | Let (x, eRhs, letBody) ->
      let xVal = eval eRhs env in
      let letEnv = (x, xVal) :: env in
      eval letBody letEnv
  | Prim (ope, e1, e2) -> (
    let v1 = eval e1 env in
    let v2 = eval e2 env in
    match (ope, v1, v2) with
    | "*", Int i1, Int i2 -> Int (i1 * i2)
    | "+", Int i1, Int i2 -> Int (i1 + i2)
    | "-", Int i1, Int i2 -> Int (i1 - i2)
    | "=", Int i1, Int i2 -> Int (if i1 = i2 then 1 else 0)
    | ">", Int i1, Int i2 -> Int (if i1 > i2 then 1 else 0)
    | "<", Int i1, Int i2 -> Int (if i1 < i2 then 1 else 0)
    | _ -> failwith "unknown primitive or wrong type")
  | If (e1, e2, e3) -> (
    match eval e1 env with
    | Int 0 -> eval e3 env
    | Int _ -> eval e2 env
    | _ -> failwith "eval if")
  | Fun (x, fBody) -> Closure (x, fBody, env)
  | Call (eFun, eArg) -> (
    let fClosure = eval eFun env in
    match fClosure with
    | Closure (x, fBody, fDeclEnv) ->
        let xVal = eval eArg env in
        let fBodyEnv = (x, xVal) :: fDeclEnv in
        eval fBody fBodyEnv
    | _ -> failwith "eval Call: not a function")
  | EncLet (ty, x, eRhs, letBody) ->
    (*TODO*)
    let xVal = eval eRhs env in
    let letEnv = (x, xVal) :: env in
    eval letBody letEnv
  | Enclave (x, eList) ->
    (*TODO*)
    let x = 1 in
    eval x
  | Gateway (funType, x, funName, eGate) ->
    (*TODO*)
    let x = 1 in
    eval x
  | IncludeUntrusted (x, eInc) ->
    (*TODO*)
    let x = 1 in
    eval x
  | ExecuteUntrusted (eExe) ->
    (*TODO*)
    let x = 1 in
    eval x
