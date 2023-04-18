(*
  Variable identifiers are strings
*)
type identifier = string

(* Implement the Map.OrderedType signature for ide *)
module IdeOrder : Map.OrderedType with type t = identifier = struct
  type t = identifier
  let compare = String.compare
end

module EnvMap = Map.Make(IdeOrder)

(*
  An environment is a map from identifier to a value (what the identifier is bound to).
  For simplicity we represent the environment as a map
*)
type 'v env = 'v EnvMap.t

(*
  Given an environment {env} and an identifier {x} it returns the data {x} is bound to.
  If there is no binding, it raises an exception.
*)
let lookup env x =
  try
    EnvMap.find x env
  with
  | Not_found -> failwith (x ^ " not found")