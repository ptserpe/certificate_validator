# Project 2
## Files description

- utils.py: contains dns and ip addresses matching helper functions, extracted from puthon ssl library

- certificate_validator.py: it takes as input a hostname and optionally the port. It validates both server certificate and chain of certificates.

```
python3 ./certificate_validator.py google.com
```

Tip: use badssl.com to validate different cases where the certificate is not valid. 