# SSL-X.509-checher
SSL X.509 checker for validity of a certificate

In order to execute the specific project you have to run the script certificate_checker.py . The script get the ssl x.509 certificate and checks if is valid. Gets the url and checks the expiration date and the issuer from the known_issuers.txt file.

```
 python certificate_checker.py -u www.google.com -i known_issuers.txt
```
