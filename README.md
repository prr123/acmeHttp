# acmeHttp

programs that interact with Let's Encrypt.
The main purpose is creating certs with a http challenge.


## createHttpCerts
usage: ./createHttpCerts /cr=<crlist> /type=prod|test /dbg

program that creates a security certificate for https containg the zones (domains) listed in the cr file.

