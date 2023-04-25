open Ast
open Env


let rec eval_gateway (e: expr) (env : value env) (secrets : value env) : int * value =
  match e with
  | CstI i -> 0, Int i
  | CstB b -> 0, Int (if b then 1 else 0)
  | Var x -> (
      try 1, lookup secrets x
      with Not_found -> 1, lookup env x
  )
  | Let (x, eRhs, letBody) -> (
      let _, xVal = eval_gateway eRhs env secrets in
      let letEnv = (x, xVal) :: env in
      eval_gateway letBody letEnv secrets
  )
  | Prim (ope, e1, e2) -> (
      let _, v1 = eval_gateway e1 env secrets in
      let _, v2 = eval_gateway e2 env secrets in
      match (ope, v1, v2) with
      | "*", Int i1, Int i2 -> 0, Int (i1 * i2)
      | "+", Int i1, Int i2 -> 0, Int (i1 + i2)
      | "-", Int i1, Int i2 -> 0, Int (i1 - i2)
      | "=", Int i1, Int i2 -> 0, Int (if i1 = i2 then 1 else 0)
      | "<", Int i1, Int i2 -> 0, Int (if i1 < i2 then 1 else 0)
      | _ -> failwith "unknown primitive or wrong type")
  | If (cond, e2, e3) -> (
      let _, ev_cond = eval_gateway cond env secrets in
      match ev_cond with
      | Int 0 -> (
          eval_gateway e3 env secrets
      )
      | Int _ -> (
          eval_gateway e2 env secrets
      )
      | _ -> failwith "eval if")
  | Fun (x, fBody) -> 0, Closure (x, fBody, env)
  | Call (eFun, eArg) -> (
      let _, fClosure = eval_gateway eFun env secrets in
      match fClosure with
      | Closure (x, fBody, fDeclEnv) ->
          (* xVal is evaluated in the current stack *)
          let _, xVal = eval_gateway eArg env secrets in
          let fBodyEnv = (x, xVal) :: fDeclEnv in

          (* fBody is evaluated in the updated stack *)
          eval_gateway fBody fBodyEnv secrets
      | _ -> failwith "eval Call: not a function"
  )

    | Enclave(_, _, _) -> failwith "Enclave definition are not allowed in a gateway. Abort"
    | EndEnclave -> failwith "Cannot close an enclave inside a gateway. Abort."
    | SecLet (_, _, _) -> failwith "Secret let is not allowed inside of an gateway. Abort."
    | Gateway(_, _, _) -> failwith "Gateway let is not allowed inside of an gateway. Abort."
    | EnCall(_, _, _) -> failwith "Enclave call are not allowed in a gateway. Abort."
    | IncludeUntrusted(_, _) -> failwith "Cannot include untrusted code inside a gateway. Abort."
    | EndUntrusted -> failwith "Cannot end untrusted code inside a gateway. Abort."
    
    
let rec eval_untrusted (e : expr) (env : value env) : value =
    match e with
    | CstI i -> Int i
    | CstB b -> Int (if b then 1 else 0)
    | Var x -> lookup env x
    | Let (x, eRhs, letBody) ->
        let xVal = eval_untrusted eRhs env in
        let letEnv = (x, xVal) :: env in
        eval_untrusted letBody letEnv
    | Prim (ope, e1, e2) -> (
        let v1 = eval_untrusted e1 env in
        let v2 = eval_untrusted e2 env in
        match (ope, v1, v2) with
        | "*", Int i1, Int i2 -> Int (i1 * i2)
        | "+", Int i1, Int i2 -> Int (i1 + i2)
        | "-", Int i1, Int i2 -> Int (i1 - i2)
        | "=", Int i1, Int i2 -> Int (if i1 = i2 then 1 else 0)
        | "<", Int i1, Int i2 -> Int (if i1 < i2 then 1 else 0)
        | _ -> failwith "unknown primitive or wrong type")
    | If (cond, e2, e3) -> (
        match eval_untrusted cond env with
        | Int 0 -> eval_untrusted e3 env
        | Int _ -> eval_untrusted e2 env
        | _ -> failwith "eval if")
    | Fun (x, fBody) -> Closure (x, fBody, env)
    | Call (eFun, eArg) -> (
        let fClosure = eval_untrusted eFun env in
        match fClosure with
        | Closure (x, fBody, fDeclEnv) ->
            (* xVal is evaluated in the current stack *)
            let xVal = eval_untrusted eArg env in
            let fBodyEnv = (x, xVal) :: fDeclEnv in
  
            (* fBody is evaluated in the updated stack *)
            eval_untrusted fBody fBodyEnv
        | _ -> failwith "eval Call: not a function"
    )

    | EndUntrusted -> UntrustedEnv(env)

    | Enclave(_, _, _) -> failwith "Cannot declare an enclave inside untrusted code. Abort."
    | EnCall(_, _, _) -> failwith "Cannot call an enclave from untrusted code. Abort."
    | EndEnclave -> failwith "Cannot end an enclave from untrusted code. Abort. "
    | SecLet (_, _, _) -> failwith "Secret let is not allowed outside of an Enclave. Abort."
    | Gateway(_, _, _) -> failwith "Gateway let is not allowed outside of an Enclave. Abort." 

    | IncludeUntrusted(_, _) -> failwith "Cannot reference untrusted code from untrusted code. Abort."
  



let rec eval (e : expr) (env : value env) (encl_list : (ide * value enclave) list) : value =
  match e with
  | CstI i -> Int i
  | CstB b -> Int (if b then 1 else 0)
  | Var x -> lookup env x
  | Let (x, eRhs, letBody) ->
      let xVal = eval eRhs env encl_list in
      let letEnv = (x, xVal) :: env in
      eval letBody letEnv encl_list
  | Prim (ope, e1, e2) -> (
      let v1 = eval e1 env encl_list in
      let v2 = eval e2 env encl_list in
      match (ope, v1, v2) with
      | "*", Int i1, Int i2 -> Int (i1 * i2)
      | "+", Int i1, Int i2 -> Int (i1 + i2)
      | "-", Int i1, Int i2 -> Int (i1 - i2)
      | "=", Int i1, Int i2 -> Int (if i1 = i2 then 1 else 0)
      | "<", Int i1, Int i2 -> Int (if i1 < i2 then 1 else 0)
      | _ -> failwith "unknown primitive or wrong type")
  | If (cond, e2, e3) -> (
      match eval cond env encl_list with
      | Int 0 -> eval e3 env encl_list
      | Int _ -> eval e2 env encl_list
      | _ -> failwith "eval if")
  | Fun (x, fBody) -> Closure (x, fBody, env)
  | EnCall(enclIde, gatewayIde, encParams) -> (
        let req_enclave = lookup encl_list enclIde in
        let req_gateway = lookup req_enclave.gateways gatewayIde in
        match req_gateway with
        | EnClosure(x,expr,secrets,generics,_) -> (
            let encParValues = eval encParams env encl_list in
            let fBodyEnv = (x, encParValues) :: env in
            match eval_gateway expr (generics @ fBodyEnv) secrets with 
                | 0, eval_gt_result -> eval_gt_result
                | _, _ -> failwith "The gateway tried to return a secret! Abort."
        )
        | _ -> failwith "Not an EnClosure, abort!"

  )
  | Call (eFun, eArg) -> (
      let fClosure = eval eFun env encl_list in
      match fClosure with
      | Closure (x, fBody, fDeclEnv) ->
          (* xVal is evaluated in the current stack *)
          let xVal = eval eArg env encl_list in
          let fBodyEnv = (x, xVal) :: fDeclEnv in

          (* fBody is evaluated in the updated stack *)
          eval fBody fBodyEnv encl_list
      | _ -> failwith "eval Call: not a function")

    | Enclave(x, enclBody, nextExpr) -> (
        let result = eval_encave enclBody [][][] in
        match result with
            | Renclave(enclaveRes) -> (
                let encList = (x, enclaveRes) ::encl_list in
                eval nextExpr env encList
            )
            | _ -> failwith "Wrong return type from enclave, maybe you are missing an EndEnclave?"
    )
    | IncludeUntrusted(inclBody, nextExpr) -> (
        let untrustVal = eval_untrusted inclBody env in
        match untrustVal with
            | UntrustedEnv(untrustEnv) -> (
                let untrustBodyEnv =  env @ untrustEnv in
                eval nextExpr untrustBodyEnv encl_list
            )
            | _ -> failwith "Wrong return type from untrusted, maybe you are missing an EndUntrusted?"
        
    ) 
    | EndEnclave -> failwith "Cannot close an enclave outside of an Enclave block. Abort."
    | SecLet (_, _, _) -> failwith "Secret let is not allowed outside of an Enclave. Abort."
    | Gateway(_, _, _) -> failwith "Gateway let is not allowed outside of an Enclave. Abort."

    | EndUntrusted -> failwith "Cannot close untrusted code outisde of an Untrusted block. Abort." 

and eval_encave (e : expr) (secrets : value env) (generics : value env) (gateways : value env) : value =
match e with
| CstI i -> Int i
| CstB b -> Int (if b then 1 else 0)
| Var x -> enclave_lookup secrets generics gateways x
| Let (x, eRhs, letBody) ->
    let xVal = eval_encave eRhs secrets generics gateways in
    let letEnv = (x, xVal) :: generics in
    eval_encave letBody secrets letEnv gateways
| SecLet (x, eRhs, letBody) ->
    let xVal = eval_encave eRhs secrets generics gateways in
    let letEnv = (x, xVal) :: secrets in
    eval_encave letBody letEnv generics gateways
| Gateway (x, eRhs, letBody) ->  (
    let xVal = eval_encave eRhs secrets generics gateways in 
    match xVal with
        | EnClosure(_, _, secrets, generics, gateways) -> (
            let letEnv = (x, xVal) :: gateways in
            eval_encave letBody secrets generics letEnv
        )
        | _ -> failwith "eval gateway: not a function. A let Gateway must be a Closure! Abort."
)
| Prim (ope, e1, e2) -> (
    let v1 = eval_encave e1 secrets generics gateways in
    let v2 = eval_encave e2 secrets generics gateways in
    match (ope, v1, v2) with
    | "*", Int i1, Int i2 -> Int (i1 * i2)
    | "+", Int i1, Int i2 -> Int (i1 + i2)
    | "-", Int i1, Int i2 -> Int (i1 - i2)
    | "=", Int i1, Int i2 -> Int (if i1 = i2 then 1 else 0)
    | "<", Int i1, Int i2 -> Int (if i1 < i2 then 1 else 0)
    | _ -> failwith "unknown primitive or wrong type")
| If (e1, e2, e3) -> (
    match eval_encave e1 secrets generics gateways with
    | Int 0 -> eval_encave e3 secrets generics gateways
    | Int _ -> eval_encave e2 secrets generics gateways
    | _ -> failwith "eval if")
| Fun (x, fBody) -> EnClosure (x, fBody, secrets, generics, gateways)
| Call (eFun, eArg) -> (
    let fClosure = eval_encave eFun secrets generics gateways in
    match fClosure with
    | EnClosure (x, fBody, fDeclSec, fDeclGen, fDeclGat) ->
        (* xVal is evaluated in the current stack *)
        let xVal = eval_encave eArg secrets generics gateways in
        let fBodyEnv = (x, xVal) :: fDeclGen in

        (* fBody is evaluated in the updated stack *)
        eval_encave fBody fDeclSec fBodyEnv fDeclGat
    | _ -> failwith "eval Call: not a function")
| EndEnclave -> Renclave({secrets; generics; gateways})
| Enclave(_, _, _) -> failwith "Cannot declare an Enclave inside another enclave! Abort."
| IncludeUntrusted(_, _) -> failwith "Cannot include untrusted code inside an enclave! Abort."
| EndUntrusted -> failwith "Cannot end untrusted inside an enclave! Abort."
| EnCall(_, _, _) -> failwith "Cannot call an enclave inside an enclave! Abort."


and enclave_lookup (secrets : value env) (generics : value env) (gateways : value env) x : value =
    try  lookup secrets x
    with Not_found ->
        try lookup generics x
        with Not_found -> lookup gateways x


