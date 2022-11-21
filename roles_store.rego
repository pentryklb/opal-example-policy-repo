package app.roles_store

import future.keywords.if

deny["store only can be accessed by store owner"] {
   not is_store_owner
}

deny["store only can be accessed by store admin"] {
   not is_store_admin
}

#opa result
result = { "messages": msg, "deny" :  denyBool}  {
  msg := {m | m := deny[_]}
  denyBool := count(msg) > 0
}

is_store_owner if input.store_uid == groups_store

is_store_admin if input.store_uid == groups_store


groups_store := split_groups(jwt.payload.groups[0])
resource_access := jwt.payload.resource_access

jwt = { "payload": payload} {
    auth_header := input.token
    [_, jwt] := split(auth_header, " ")
    [_, payload, _] := io.jwt.decode(jwt)
}

split_groups(groups) := x {
  parts := split(groups, "/")
  x := parts[2]
}
