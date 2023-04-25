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
    "f", 
    Fun (
      "x",
      Prim ("+", Var "x", CstI 1)
    ) 
    ,
    Gateway ("password", Var ("f"), EndEnclave)
  ), CstI(7)
)

let _test_gateway_3 = Enclave (
  "myEnclave",
   SecLet (
    "password", CstI(5),
    Gateway ("password", Fun ("leak", Var ("password")), EndEnclave)
  ), CstI(7)
)

let _value_1 = eval _test_gateway_3 [] []