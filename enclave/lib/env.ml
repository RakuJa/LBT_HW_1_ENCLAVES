type ide = string

type 'v env = (ide * 'v) list

let rec lookup env x =
  match env with
  | [] -> failwith (x ^ " not found")
  | (y, v) :: r -> if x = y then v else lookup r x
