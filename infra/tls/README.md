# TLS mount point

Production certificates are operator-managed runtime inputs. Do not commit a
certificate, private key, internal CA, or generated test material here. Point
`TLS_CERT_PATH` and `TLS_KEY_PATH` in the untracked production environment file
at protected host files instead.
