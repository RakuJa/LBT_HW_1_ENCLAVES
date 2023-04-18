open Ast
open Env

type envList = 
  { secEnv : value env;
    trustEnv : value env;
    untrustEnv : value env;
  }