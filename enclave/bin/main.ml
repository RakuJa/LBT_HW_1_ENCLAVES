open Enclave.Ast
open Enclave.Interpreter

let _test_gateway_1 = Enclave (
  "myEnclave",
   SecLet (
    "password", CstI(5),
   Gateway ("password", CstI(5), EndEnclave)
  ), CstI(7)
)

let _test_gateway_2 = Enclave (
  "myEnclave",
  SecLet (
   "x", CstI (1),
   SecLet (
    "f", 
    Fun (
      "y",
      Prim ("+", Var ("x") , CstI 1)
    ) 
    ,
   Gateway ("myGateway", Var ("f"), EndEnclave)
  )), EnCall ("myEnclave", "myGateway", CstI (1))
)

let _test_gateway_3 = Enclave (
  "myEnclave",
   SecLet (
   "password", CstI(5),
   Gateway ("myGateway", Fun ("leak", Var ("password")), EndEnclave)
  ), EnCall ("myEnclave", "myGateway", CstI (1))
)

let _test_gateway_4 = Gateway 
   ("myGateway", Fun ("outside", Var ("password")), CstI (1))

let _test_enclave_1 = Enclave (
   "myEnclave1",
   SecLet (
    "password", CstI(5),
   Enclave ("myEnclave2", CstI(5), EndEnclave)
  ), CstI(7)
)

let _test_enclave_2 = Enclave (
  "myEnclave", CstI (1), CstI (2)
)

let _test_untrusted_1 = IncludeUntrusted (
   Let ("x", CstI (1), EndUntrusted), CstI (1)
)

let _test_untrusted_2 = IncludeUntrusted (
   IncludeUntrusted (CstI (1), EndUntrusted), EndUntrusted
)

let _test_untrusted_3 = Enclave (
  "myEnclave",
  SecLet (
   "x", CstI (1),
   SecLet (
    "f", 
    Fun (
      "y",
      Prim ("+", Var ("x") , CstI 1)
    ) 
    ,
   Gateway ("myGateway", Var ("f"), EndEnclave)
  )), IncludeUntrusted (EnCall ("myEnclave", "myGateway", CstI (1)), EndUntrusted
))

(*
let _test_1 = eval _test_gateway_1 [] []
let _test_2 = eval _test_gateway_2 [] []
let _test_3 = eval _test_gateway_3 [] []
let _test_4 = eval _test_gateway_4 [] []
let _test_5 = eval _test_enclave_1 [] []
let _test_6 = eval _test_enclave_2 [] []
let _test_7 = eval _test_untrusted_1 [] []
let _test_8 = eval _test_untrusted_2 [] []
let _test_9 = eval _test_untrusted_3 [] []
*)