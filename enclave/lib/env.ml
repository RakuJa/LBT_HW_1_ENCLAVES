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
  An environment is a map from identifier to {value, sec_level}  (what the identifier is bound to).
  For simplicity we represent the environment as an association list, i.e., a list of (identifier, data, sec_level).
*)

type 'v env = (ide * 'v ) list
type 'v enclave = {secrets: (ide * 'v ) list; generics: (ide * 'v ) list; gateways: (ide * 'v) list}

(*
  Given an environment {env} and an identifier {x} it returns the data {x} is bound to and its security level {sec}.
  If there is no binding, it raises an exception.
*)
let rec lookup env x: 'v =
  match env with
  | [] -> failwith (x ^ " not found")
  | (y, v) :: r -> if x = y then v else lookup r x