(*
  Variable identifiers are strings
*)
type ide = string

(*
  Values for confidentiality, either high-security or low-security
*)
type sec_level =
  | Low
  | High

(*
  An environment is a map from identifier to a value (what the identifier is bound to).
  For simplicity we represent the environment as an association list, i.e., a list of pair (identifier, data, security_level).
*)

type 'v env = (ide * 'v * sec_level) list
type 'v enclave = {secrets: (ide * 'v * sec_level) list; generics: (ide * 'v * sec_level) list; gateways: (ide * 'v * sec_level) list}

(*
  Given an environment {env} and an identifier {x} it returns the data {x} is bound to and its security level {sec}.
  If there is no binding, it raises an exception.
*)
let rec lookup env x: 'v =
  match env with
  | [] -> failwith (x ^ " not found")
  | (y, v, sec) :: r -> if x = y then (v, sec) else lookup r x