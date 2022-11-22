package app.medhis

import future.keywords.if

default relationship_endpoint := "https://user-api.medkomtek-stg.com/user-svc/api/v1/users/list-relationship"
default is_relationship := false

deny["medical history only can be accessed by owner or its relationship"] {
   not is_owner 
   not is_relationship
}

#opa result
result = { "messages": msg, "deny" :  denyBool}  {
  msg := {m | m := deny[_]}
  denyBool := count(msg) > 0
}

#check owner
is_owner if input.uid == jwt.payload.id

#check relationship
is_relationship {
    relationship.body.data.records[_].user_uid == input.uid
}

headers = {
    "Content-Type": "application/json",
    "Authorization": input.token,
    "Accept": "application/json"
}

records = relationship.data.records

relationship = http.send(
  {
  "method": "get",
  "url": relationship_endpoint,
  "headers": headers
  }
)

jwt = { "payload": payload} {
    auth_header := input.token
    [_, jwt] := split(auth_header, " ")
    [_, payload, _] := io.jwt.decode(jwt)
}
