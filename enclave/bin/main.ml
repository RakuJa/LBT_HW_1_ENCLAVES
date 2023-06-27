open Enclave.Ast
open Enclave.Interpreter

(*
  For testing purpose: test if the evaluation fails
*)
let execWithFailure test env stack =
  let value = try eval test env stack with Failure _ -> Int (1, Low) in
  assert (value = Int (1, Low))

  (*
    For testing purpose: test if the evaluation does not fail
  *)
let execWithoutFailure test env stack =
  let value = try eval test env stack with Failure _ -> Int (0, Low) in
  assert (value <> Int (0, Low))

let examples =
  [
    execWithFailure (
      print_endline "_test_gateway_1";
      Enclave (
        "myEnclave",
        SecLet (
          "password", CstI(5, High),
          Gateway ("password", CstI(5, High), EndEnclave)
        ), CstI(7, High)
      )
    ) [] [];
    execWithoutFailure (
      print_endline "_test_gateway_2";
      Enclave (
        "myEnclave",
        SecLet (
          "x", CstI (1, Low),
          SecLet (
            "f", 
            Fun (
              "y",
              Prim ("+", Var ("x") , CstI(1, Low))
            ) 
            ,
            Gateway ("myGateway", Var ("f"), EndEnclave)
          )), EnCall ("myEnclave", "myGateway", CstI (1, High))
      )
    ) [] [];
    execWithFailure (
      print_endline "_test_gateway_3";
      Enclave (
        "myEnclave",
        SecLet (
          "password", CstI(5, High),
          Gateway ("myGateway", Fun ("leak", Var ("password")), EndEnclave)
        ), EnCall ("myEnclave", "myGateway", CstI (1, High))
      )
    ) [] [];
    execWithFailure (
      print_endline "_test_gateway_4";
      Gateway 
        ("myGateway", Fun ("outside", Var ("password")), CstI (1, High))
    ) [] [];
    execWithFailure (
      print_endline "_test_enclave_1";
      Enclave (
        "myEnclave1",
        SecLet (
          "password", CstI(5, High),
          Enclave ("myEnclave2", CstI(5, High), EndEnclave)
        ), CstI(7, High)
      )
    ) [] [];
    execWithFailure (
      print_endline "_test_enclave_2";
      Enclave (
        "myEnclave", CstI (1, High), CstI (2, High)
      )
    ) [] [];      
    execWithoutFailure (
      print_endline "_test_untrusted_1";
      IncludeUntrusted (
        Let ("x", CstI (1, High), EndUntrusted), CstI (1, High)
      )
    ) [] [];
    execWithFailure (
      print_endline "_test_untrusted_2";
      IncludeUntrusted (
        IncludeUntrusted (CstI (1, High), EndUntrusted), EndUntrusted
      )
    ) [] [];
    execWithFailure (
      print_endline "_test_untrusted_3";
      Enclave (
        "myEnclave",
        SecLet (
          "x", CstI (1, High),
          SecLet (
            "f", 
            Fun (
              "y",
              Prim (
                "+", Var ("x") , CstI (1, High)
              )
            ),
            Gateway (
              "myGateway", Var ("f"), EndEnclave
            )
          )
        ), 
        IncludeUntrusted (
          EnCall (
            "myEnclave", "myGateway", CstI (1, High)
          ), 
          EndUntrusted
        )
      )
    ) [] [];


    (* Declassify test *)

    execWithoutFailure (
      print_endline "_test_declassify_1";
      Declassify (
        Prim ("+", CstI(1, High), CstI(2, High))
      )
    ) [] [];
    execWithFailure (
      print_endline "_test_declassify_2";
      Declassify (
        Prim ("+", CstI(1, Low), CstI(2, Low))
      )
    ) [] [];


    (* If test *)

    execWithoutFailure (
      print_endline "_test_if_1_high_guard_all_high_branch";
      Let ("x", CstI(1, High), 
           If (
             Prim ("<", Var("x"), CstI(2, High)), CstI(2, High), CstI(3, High)
           )
          )
    ) [] [];
    execWithoutFailure (
      print_endline "_test_if_2";
      Let ("x", CstI(1, Low), 
           If (
             Prim ("<", Var("x"), CstI(2, Low)), CstI(2, Low), CstI(3, Low)
           )
          )
    ) [] [];
    execWithFailure (
      print_endline "_test_if_2_high_guard_all_low_branch";
      Let ("x", CstI(1, High), 
           If (
             Prim ("=", Var("x"), CstI(2, High)), CstB(true, Low), CstB (false, Low)
           )
          )
    ) [] [];
    execWithoutFailure (
      print_endline "_test_if_3_high_guard_a_branch_low_b_branch_high";
      Let ("x", CstI(1, High), 
           If (
             Prim ("=", Var("x"), CstI(2, High)), CstB(true, Low), CstB (false, High)
           )
          )
    ) [] [];
    execWithFailure (
      print_endline "_test_if_4_high_guard_b_branch_low_a_branch_high";
      Let ("x", CstI(1, High), 
           If (
             Prim ("=", Var("x"), CstI(2, High)), CstB(true, High), CstB (false, Low)
           )
          )
    ) [] [];

    (* Prim test *)

    execWithoutFailure (
      print_endline "_test_prim_1_comp_high_with_high_and_equals";
      Prim (
        "=", CstI(2, High), CstI(2, High)
      )
    ) [] [];


    execWithoutFailure (
      print_endline "_test_prim_2_comp_low_with_low_and_equals";
      Prim (
        "=", CstI(2, Low), CstI(2, Low)
      )
    ) [] [];

    execWithFailure (
      print_endline "_test_prim_3_comp_high_with_low_and_equals";
      Prim (
        "=", CstI(2, High), CstI(2, Low)
      )
    ) [] [];

    execWithFailure (
      print_endline "_test_prim_4_comp_low_with_high_and_equals";
      Prim (
        "=", CstI(2, Low), CstI(2, High)
      )
    ) [] [];


    execWithoutFailure (
      print_endline "_test_prim_1_sum_high_with_high_and_equals";
      Prim (
        "+", CstI(2, High), CstI(2, High)
      )
    ) [] [];


    execWithoutFailure (
      print_endline "_test_prim_2_sum_low_with_low_and_equals";
      Prim (
        "+", CstI(2, Low), CstI(2, Low)
      )
    ) [] [];

    execWithFailure (
      print_endline "_test_prim_3_sum_high_with_low_and_equals";
      Prim (
        "+", CstI(2, High), CstI(2, Low)
      )
    ) [] [];

    execWithFailure (
      print_endline "_test_prim_4_sum_low_with_high_and_equals";
      Prim (
        "+", CstI(2, Low), CstI(2, High)
      )
    ) [] [];


    (* Test funcall *)

    execWithoutFailure (
      print_endline "_test_funcall_1";
      Call (
        Fun ("f", CstI(1, High)), CstB(false, Low)
      )
    ) [] [];
  ]

let rec execute_examples ex =
  print_endline "Running test case";
  match ex with
  | [] -> print_endline "Done"
  | x :: t ->
    x;
    execute_examples t

let _ = print_endline "--------------\nStarting tests"
let () = execute_examples examples
