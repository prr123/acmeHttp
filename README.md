# acmeHttp

programs that interact with Let's Encrypt.
The main purpose is creating certs with a http challenge.

The program assumes that an LE account has been created. 
To create an LE account see repositarty LEAccount.

## createHttpCerts
usage: ./createHttpCerts /cr=crname /type=prod|test /dbg

program that creates a security certificate for https containg the zones (domains) listed in the cr file.
A cr name should be the name of the domain using an underscore to separate the  primary from tht secondary:  
example: domain: example.com => crname: example_com.cr 
