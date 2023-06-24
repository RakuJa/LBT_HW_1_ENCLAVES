open Ast
open Env

let rec eval_gateway (e: expr) (env : value env) (secrets : value env) : int * value =
  match e with
  | CstI (i, sec) -> 0, Int (i, sec)
  | CstB (b, sec) -> 0, Int ((if b then 1 else 0), sec)
  | Var x -> (
      try 
        let v, _ = lookup secrets x in 1, v
      with Not_found -> 
        let v, _ = lookup env x in 1, v
    )
  (*using "High" as default sec_level*)
  | Let (x, eRhs, letBody) -> (
      let _, xVal = eval_gateway eRhs env secrets in
      let letEnv = (x, xVal, High) :: env in
      eval_gateway letBody letEnv secrets
    )
  (*if either operand is high-security, the result is high-security; otherwise, it is marked as low-security*)
  | Prim (ope, e1, e2) -> (
      let _, v1 = eval_gateway e1 env secrets in
      let _, v2 = eval_gateway e2 env secrets in
      match (ope, v1, v2) with
      | "*", Int (i1, sec1), Int (i2, sec2) ->
        let sec = if sec1 = High || sec2 = High then High else Low in
        0, Int (i1 * i2, sec)
      | "+", Int (i1, sec1), Int (i2, sec2) ->
        let sec = if sec1 = High || sec2 = High then High else Low in
        0, Int (i1 + i2, sec)
      | "-", Int (i1, sec1), Int (i2, sec2) ->
        let sec = if sec1 = High || sec2 = High then High else Low in
        0, Int (i1 - i2, sec)
      | "=", Int (i1, sec1), Int (i2, sec2) ->
        let sec = if sec1 = High || sec2 = High then High else Low in
        0, Int ((if i1 = i2 then 1 else 0), sec)
      | "<", Int (i1, sec1), Int (i2, sec2) ->
        let sec = if sec1 = High || sec2 = High then High else Low in
        0, Int ((if i1 < i2 then 1 else 0), sec)
      | _ -> failwith "unknown primitive or wrong type"
    )
  (*prevent the evaluation of High sec_level to prevent leakage*)
  | If (cond, e2, e3) -> (
      let _, ev_cond = eval_gateway cond env secrets in
      match ev_cond with
      | Int (0, _) ->
        let _, v3 = eval_gateway e3 env secrets in
        (match v3 with
         | Int (_, sec3) -> if sec3 = High then failwith "High-security value leaked in If branch" else 0, v3
         | _ -> failwith "Non-integer value")
      | Int (_, _) ->
        let _, v2 = eval_gateway e2 env secrets in
        (match v2 with
         | Int (_, sec2) -> if sec2 = High then failwith "High-security value leaked in If branch" else 0, v2
         | _ -> failwith "Non-integer value")
      | _ -> failwith "eval if"
    )
  | Fun (x, fBody) -> 0, Closure (x, fBody, env)
  (*using "High" as default sec_level*)
  | Call (eFun, eArg) -> (
      let _, fClosure = eval_gateway eFun env secrets in
      match fClosure with
      | Closure (x, fBody, fDeclEnv) ->
        let _, xVal = eval_gateway eArg env secrets in
        let fBodyEnv = (x, xVal, High) :: fDeclEnv in
        eval_gateway fBody fBodyEnv secrets
      | _ -> failwith "eval Call: not a function"
    )
  (*Change a High value to Low, fail if already Low*)
  | Declassify e -> (
      let _, v = eval_gateway e env secrets in
      match v with
      | Int (i, High) -> 0, Int (i, Low)
      | _ -> failwith "Cannot declassify a non-high-security value"
    )
  | Enclave(_, _, _) -> failwith "Enclave definitions are not allowed in a gateway. Abort."
  | EndEnclave -> failwith "Cannot close an enclave inside a gateway. Abort."
  | SecLet (_, _, _) -> failwith "Secret let is not allowed inside a gateway. Abort."
  | Gateway(_, _, _) -> failwith "Gateway let is not allowed inside a gateway. Abort."
  | EnCall(_, _, _) -> failwith "Enclave calls are not allowed in a gateway. Abort."
  | IncludeUntrusted(_, _) -> failwith "Cannot include untrusted code inside a gateway. Abort."
  | EndUntrusted -> failwith "Cannot end untrusted code inside a gateway. Abort."

