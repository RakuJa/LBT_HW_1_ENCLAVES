open Enclave.Ast
open Enclave.Interpreter
(* Enclave myEncl = *)
let test = Enclave (
  "myEnclave",
   SecLet (
    "password", CstI(5),
    Gateway ("password", CstI(5), EndEnclave)
  ), CstI(7)
  
)

(* let myEncl = Enclave {
   SecLet password = 5 in
   Let x = 6 in 4
   End


}
   
   
   *)
let _value = eval test [] []