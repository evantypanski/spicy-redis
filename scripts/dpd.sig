signature resp-serialized-server {
  ip-proto == tcp
  payload /[+-:$*_#,(!=%`~>].*\r\n/
  event "Found Redis server data"
  enable "spicy_Redis"
}
