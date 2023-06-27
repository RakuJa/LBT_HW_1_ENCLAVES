open Ast
open Env

let rec eval_gateway (e: expr) (env : value env) (secrets : value env) : value =
  match e with
  | CstI (i, sec) -> Int (i, sec)
  | CstB (b, sec) -> Int ((if b then 1 else 0), sec)
  | Var x -> (
      try 
        lookup secrets x

      with Not_found -> 
        lookup env x
    )
  | Let (x, eRhs, letBody) -> (
      let xVal = eval_gateway eRhs env secrets in
      let letEnv = (x, xVal) :: env in
      eval_gateway letBody letEnv secrets
    )
  | Prim (ope, e1, e2) -> (
      let v1 = eval_gateway e1 env secrets in
      let v2 = eval_gateway e2 env secrets in
      match (ope, v1, v2) with
      | "*", Int (i1, High), Int (i2, High) -> Int(i1 * i2, High)
      | "*", Int (i1, Low), Int (i2, Low) -> Int(i1 * i2, Low)
      | "*", _, _ -> failwith "Cannot use a low value together with a high value" 

      | "+", Int (i1, High), Int (i2, High) -> Int(i1 + i2, High)
      | "+", Int (i1, Low), Int (i2, Low) -> Int(i1 + i2, Low)
      | "+", _, _ -> failwith "Cannot use a low value together with a high value" 

      | "-", Int (i1, High), Int (i2, High) -> Int(i1 - i2, High)
      | "-", Int (i1, Low), Int (i2, Low) -> Int(i1 - i2, Low)
      | "-", _, _ -> failwith "Cannot use a low value together with a high value"  

      | "=", Int (i1, High), Int (i2, High) -> Int((if i1 = i2 then 1 else 0), High)
      | "=", Int (i1, Low), Int (i2, Low) -> Int((if i1 = i2 then 1 else 0), Low)
      | "=", _, _ -> failwith "Cannot use a low value together with a high value" 


      | "<", Int (i1, High), Int (i2, High) -> Int((if i1 < i2 then 1 else 0), High)
      | "<", Int (i1, Low), Int (i2, Low) -> Int((if i1 < i2 then 1 else 0), Low)
      | "<", _, _ -> failwith "Cannot use a low value together with a high value" 
      | _ -> failwith "unknown primitive or wrong type"
    )
  | If (cond, e2, e3) -> (
      let ev_cond = eval_gateway cond env secrets in
      match ev_cond with
      | Int (0, cond_lvl) ->
        let v3 = eval_gateway e3 env secrets in
        (match v3 with
         | Int (_, Low) -> (
             match cond_lvl with
             | High -> failwith "Low security branch had high security guard"
             | _ -> v3
           ) 
         | Int (_, High) -> v3
         | _ -> failwith "Non-integer value")
      | Int (_, cond_lvl) ->
        let v2 = eval_gateway e2 env secrets in (
          match v2 with
          | Int (_, Low) -> (
              match cond_lvl with
              | High -> failwith "Low security branch had high security guard"
              | _ -> v2
            ) 
          | Int (_, High) -> v2
          | _ -> failwith "Non-integer value"
        )
      | _ -> failwith "eval if"
    )
  | Fun (x, fBody) -> Closure (x, fBody, env)
  | Call (eFun, eArg) -> (
      let fClosure = eval_gateway eFun env secrets in
      match fClosure with
      | Closure (x, fBody, fDeclEnv) -> (
          let xVal = eval_gateway eArg env secrets in
          let fBodyEnv = (x, xVal) :: fDeclEnv in
          eval_gateway fBody fBodyEnv secrets
        )
      | _ -> failwith "eval Call: not a function"
    )
  | Declassify e -> (
      let v = eval_gateway e env secrets in
      match v with
      | Int (i, High) -> Int (i, Low)
      | _ -> failwith "Cannot declassify a non-high-security value"
    )
  | Enclave(_, _, _) -> failwith "Enclave definitions are not allowed in a gateway. Abort."
  | EndEnclave -> failwith "Cannot close an enclave inside a gateway. Abort."
  | SecLet (_, _, _) -> failwith "Secret let is not allowed inside a gateway. Abort."
  | Gateway(_, _, _) -> failwith "Gateway let is not allowed inside a gateway. Abort."
  | EnCall(_, _, _) -> failwith "Enclave calls are not allowed in a gateway. Abort."
  | IncludeUntrusted(_, _) -> failwith "Cannot include untrusted code inside a gateway. Abort."
  | EndUntrusted -> failwith "Cannot end untrusted code inside a gateway. Abort."

let rec eval_untrusted (e : expr) (env : value env) : value =
  match e with
  | CstI (i, sec) -> (
      match(sec) with 
      | High -> failwith "Cannot have high value inside untrusted code"
      | _ -> Int (i, Low)
    )
  | CstB (b, sec) -> (
      match(sec) with 
      | High -> failwith "Cannot have high value inside untrusted code"
      | _ -> Int ((if b then 1 else 0), Low)
    ) 
  | Var x -> lookup env x
  | Let (x, eRhs, letBody) ->
    let xVal = eval_untrusted eRhs env in
    let letEnv = (x, xVal) :: env in
    eval_untrusted letBody letEnv
  | Prim (ope, e1, e2) -> (
      let v1 = eval_untrusted e1 env in
      let v2 = eval_untrusted e2 env in
      match (ope, v1, v2) with
      | "*", Int (i1, Low), Int (i2, Low) -> Int(i1 * i2, Low)
      | "*", _, _ -> failwith "Cannot use a high value in untrusted code" 

      | "+", Int (i1, Low), Int (i2, Low) -> Int(i1 + i2, Low)
      | "+", _, _ -> failwith "Cannot use a high value in untrusted code" 

      | "-", Int (i1, Low), Int (i2, Low) -> Int(i1 - i2, Low)
      | "-", _, _ -> failwith "Cannot use a high value in untrusted code"  

      | "=", Int (i1, Low), Int (i2, Low) -> Int((if i1 = i2 then 1 else 0), Low)
      | "=", _, _ -> failwith "Cannot use a high value in untrusted code"  

      | "<", Int (i1, Low), Int (i2, Low) -> Int((if i1 < i2 then 1 else 0), Low)
      | "<", _, _ -> failwith "Cannot use a high value in untrusted code"  
      | _ -> failwith "unknown primitive or wrong type"
    )
  | If (cond, e2, e3) -> (
      match eval_untrusted cond env with
      | Int (0, _) -> eval_untrusted e3 env
      | Int (_, _) -> eval_untrusted e2 env
      | _ -> failwith "eval if"
    )
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
  | EndUntrusted -> UntrustedEnv env
  | Declassify _ -> failwith "Cannot declassify a non-high-security value"
  | Enclave(_, _, _) -> failwith "Cannot declare an enclave inside untrusted code. Abort."
  | EnCall(_, _, _) -> failwith "Cannot call an enclave from untrusted code. Abort."
  | EndEnclave -> failwith "Cannot end an enclave from untrusted code. Abort. "
  | SecLet (_, _, _) -> failwith "Secret let is not allowed outside of an Enclave. Abort."
  | Gateway(_, _, _) -> failwith "Gateway let is not allowed outside of an Enclave. Abort." 
  | IncludeUntrusted(_, _) -> failwith "Cannot reference untrusted code from untrusted code. Abort."

let rec eval (e : expr) (env : value env) (encl_list : (ide * value enclave) list) : value =
  match e with
  | CstI (i, sec) -> Int (i, sec)
  | CstB (b, sec) -> Int ((if b then 1 else 0), sec)
  | Var x -> lookup env x
  | Let (x, eRhs, letBody) ->
    let xVal = eval eRhs env encl_list in
    let letEnv = (x, xVal) :: env in
    eval letBody letEnv encl_list
  | Prim (ope, e1, e2) -> (
      let v1 = eval e1 env encl_list in
      let v2 = eval e2 env encl_list in
      match (ope, v1, v2) with
      | "*", Int (i1, High), Int (i2, High) -> Int(i1 * i2, High)
      | "*", Int (i1, Low), Int (i2, Low) -> Int(i1 * i2, Low)
      | "*", _, _ -> failwith "Cannot use a low value together with a high value" 

      | "+", Int (i1, High), Int (i2, High) -> Int(i1 + i2, High)
      | "+", Int (i1, Low), Int (i2, Low) -> Int(i1 + i2, Low)
      | "+", _, _ -> failwith "Cannot use a low value together with a high value" 

      | "-", Int (i1, High), Int (i2, High) -> Int(i1 - i2, High)
      | "-", Int (i1, Low), Int (i2, Low) -> Int(i1 - i2, Low)
      | "-", _, _ -> failwith "Cannot use a low value together with a high value"  

      | "=", Int (i1, High), Int (i2, High) -> Int((if i1 = i2 then 1 else 0), High)
      | "=", Int (i1, Low), Int (i2, Low) -> Int((if i1 = i2 then 1 else 0), Low)
      | "=", _, _ -> failwith "Cannot use a low value together with a high value" 


      | "<", Int (i1, High), Int (i2, High) -> Int((if i1 < i2 then 1 else 0), High)
      | "<", Int (i1, Low), Int (i2, Low) -> Int((if i1 < i2 then 1 else 0), Low)
      | "<", _, _ -> failwith "Cannot use a low value together with a high value" 


      | _ -> failwith "unknown primitive or wrong type"
    )

  | If (cond, e2, e3) -> (
      let ev_cond = eval cond env encl_list in
      match ev_cond with
      | Int (0, cond_lvl) ->
        let v3 = eval e3 env encl_list in (
          match v3 with 
          | Int (_, Low) -> (
              match cond_lvl with
              | High -> failwith "Low security branch had high security guard"
              | _ -> v3
            ) 
          | Int (_, High) -> v3
          | _ -> failwith "Non-integer value")
      | Int (_, cond_lvl) ->
        let v2 = eval e2 env encl_list in
        (match v2 with
         | Int (_, Low) -> (
             match cond_lvl with
             | High -> failwith "Low security branch had high security guard"
             | _ -> v2
           ) 
         | Int (_, High) -> v2
         | _ -> failwith "Non-integer value")
      | _ -> failwith "eval if"
    )
  | Fun (x, fBody) -> Closure (x, fBody, env)
  | EnCall (enclIde, gatewayIde, encParams) -> (
      let req_enclave = lookup encl_list enclIde in
      let req_gateway = lookup req_enclave.gateways gatewayIde in
      match req_gateway with
      | EnClosure (x, expr, secrets, generics, _) -> (
          let encParValues = eval encParams env encl_list in
          match encParValues with
          | Int(_, High) -> (
              let fBodyEnv = (x, encParValues) :: env in
              match eval_gateway expr (generics @ fBodyEnv) secrets with 
              | eval_gt_result -> 
                match (eval_gt_result) with
                | Int (_, sec_lvl) -> (
                    match (sec_lvl) with
                    | Low -> eval_gt_result
                    | _ -> failwith "The gateway tried to return a secret! Abort."
                  )
                | Closure(_) -> eval_gt_result
                | _ -> failwith "Operation not allowed! Abort."
            )
          | _ -> (
              let fBodyEnv = (x, encParValues) :: env in
              match eval_gateway expr (generics @ fBodyEnv) secrets with 
              | eval_gt_result -> 
                match (eval_gt_result) with
                | Int (_, sec_lvl) -> (
                    match (sec_lvl) with
                    | Low -> eval_gt_result
                    | _ -> failwith "The gateway tried to return a secret! Abort."
                  )
                | Closure(_) -> eval_gt_result
                | _ -> failwith "Operation not allowed! Abort."
            )
        )
      | _ -> failwith "Not an EnClosure, abort!"
    )
  | Call (eFun, eArg) -> (
      let fClosure = eval eFun env encl_list in
      match fClosure with
      | Closure (x, fBody, fDeclEnv) -> (
          (* xVal is evaluated in the current stack *)
          let xVal = eval eArg env encl_list in
          let fBodyEnv = (x, xVal) :: fDeclEnv in
          eval fBody fBodyEnv encl_list
        )
      | _ -> failwith "eval Call: not a function"
    )


  | Enclave (x, enclBody, nextExpr) -> (
      let result = eval_enclave enclBody [][][] in
      match result with
      | Renclave (enclaveRes) -> (
          let encList = (x, enclaveRes) :: encl_list in
          eval nextExpr env encList
        )
      | _ -> failwith "Wrong return type from enclave, maybe you are missing an EndEnclave?")
  | IncludeUntrusted (inclBody, nextExpr) -> (
      let untrustVal = eval_untrusted inclBody env in
      match untrustVal with
      | UntrustedEnv (untrustEnv) -> (
          let untrustBodyEnv = untrustEnv in
          eval nextExpr untrustBodyEnv encl_list
        )
      | _ -> failwith "Wrong return type from untrusted, maybe you are missing an EndUntrusted?")
  | Declassify e -> (
      match eval e env encl_list with
      | Int (i, High) -> Int (i, Low)
      | _ -> failwith "Cannot declassify a non-high-security value"
    )
  | EndEnclave -> failwith "Cannot close an enclave outside of an Enclave block. Abort."
  | SecLet (_, _, _) -> failwith "Secret let is not allowed outside of an Enclave. Abort."
  | Gateway(_, _, _) -> failwith "Gateway let is not allowed outside of an Enclave. Abort."
  | EndUntrusted -> failwith "Cannot close untrusted code outside of an Untrusted block. Abort."

and eval_enclave (e : expr) (secrets : value env) (generics : value env) (gateways : value env) : value =
  match e with
  | CstI (i, sec) -> Int (i, sec)
  | CstB (b, sec) -> Int ((if b then 1 else 0), sec)
  | Var x -> enclave_lookup secrets generics gateways x
  | Let (x, eRhs, letBody) ->
    let xVal = eval_enclave eRhs secrets generics gateways in
    let letEnv = (x, xVal) :: generics in
    eval_enclave letBody secrets letEnv gateways
  | SecLet (x, eRhs, letBody) ->
    let xVal = eval_enclave eRhs secrets generics gateways in
    let letEnv = (x, xVal) :: secrets in
    eval_enclave letBody letEnv generics gateways
  | Gateway (x, eRhs, letBody) ->  (
      let xVal = eval_enclave eRhs secrets generics gateways in 
      match xVal with
      | EnClosure(_, _, secrets, generics, gateways) -> (
          let letEnv = (x, xVal) :: gateways in
          eval_enclave letBody secrets generics letEnv
        )
      | _ -> failwith "eval gateway: not a function. A let Gateway must be a Closure! Abort."
    )
  | Prim (ope, e1, e2) -> (
      let v1 = eval_enclave e1 secrets generics gateways in
      let v2 = eval_enclave e2 secrets generics gateways in
      match (ope, v1, v2) with
      | "*", Int (i1, High), Int (i2, High) -> Int(i1 * i2, High)
      | "*", Int (i1, Low), Int (i2, Low) -> Int(i1 * i2, Low)
      | "*", _, _ -> failwith "Cannot use a low value together with a high value" 

      | "+", Int (i1, High), Int (i2, High) -> Int(i1 + i2, High)
      | "+", Int (i1, Low), Int (i2, Low) -> Int(i1 + i2, Low)
      | "+", _, _ -> failwith "Cannot use a low value together with a high value" 

      | "-", Int (i1, High), Int (i2, High) -> Int(i1 - i2, High)
      | "-", Int (i1, Low), Int (i2, Low) -> Int(i1 - i2, Low)
      | "-", _, _ -> failwith "Cannot use a low value together with a high value"  

      | "=", Int (i1, High), Int (i2, High) -> Int((if i1 = i2 then 1 else 0), High)
      | "=", Int (i1, Low), Int (i2, Low) -> Int((if i1 = i2 then 1 else 0), Low)
      | "=", _, _ -> failwith "Cannot use a low value together with a high value" 


      | "<", Int (i1, High), Int (i2, High) -> Int((if i1 < i2 then 1 else 0), High)
      | "<", Int (i1, Low), Int (i2, Low) -> Int((if i1 < i2 then 1 else 0), Low)
      | "<", _, _ -> failwith "Cannot use a low value together with a high value" 
      | _ -> failwith "unknown primitive or wrong type"
    )
  | If (cond, e2, e3) -> (
      let ev_cond = eval_enclave cond secrets generics gateways in
      match ev_cond with
      | Int (0, cond_lvl) ->
        let v3 = eval_enclave e3 secrets generics gateways in (
          match v3 with 
          | Int (_, Low) -> (
              match cond_lvl with
              | High -> failwith "Low security branch had high security guard"
              | _ -> v3
            ) 
          | Int (_, High) -> v3
          | _ -> failwith "Non-integer value")
      | Int (_, cond_lvl) ->
        let v2 = eval_enclave e2 secrets generics gateways in (
          match v2 with
          | Int (_, Low) -> (
              match cond_lvl with
              | High -> failwith "Low security branch had high security guard"
              | _ -> v2
            ) 
          | Int (_, High) -> v2
          | _ -> failwith "Non-integer value")
      | _ -> failwith "eval if"
    )
  | Fun (x, fBody) -> EnClosure (x, fBody, secrets, generics, gateways)
  | Call (eFun, eArg) -> (
      let fClosure = eval_enclave eFun secrets generics gateways in
      match fClosure with
      | EnClosure (x, fBody, fDeclSec, fDeclGen, fDeclGat) -> (
          (* xVal is evaluated in the current stack *)
          let xVal = eval_enclave eArg secrets generics gateways in
          let fBodyEnv = (x, xVal) :: fDeclGen in
          eval_enclave fBody fDeclSec fBodyEnv fDeclGat
        )
      | _ -> failwith "eval Call: not a function"
    )
  | Declassify e -> (
      match eval_enclave e secrets generics gateways with
      | Int (i, High) -> Int (i, Low)
      | _ -> failwith "Cannot declassify a non-high-security value"
    )
  | EndEnclave -> Renclave ({ secrets; generics; gateways })
  | Enclave (_, _, _) -> failwith "Cannot declare an Enclave inside another enclave! Abort."
  | IncludeUntrusted (_, _) -> failwith "Cannot include untrusted code inside an enclave! Abort."
  | EndUntrusted -> failwith "Cannot end untrusted inside an enclave! Abort."
  | EnCall (_, _, _) -> failwith "Cannot call an enclave inside an enclave! Abort."


and enclave_lookup (secrets : value env) (generics : value env) (gateways : value env) x : value =
  try 
    lookup secrets x
  with Not_found ->
  try
    lookup generics x
  with Not_found -> 
    lookup gateways x