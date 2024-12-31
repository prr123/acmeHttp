# acmeDnsV2

programs that interact with Let's Encrypt.
The main purpose is creating certs with a DNS challenge.
The programs are limited to domains (zones) whose nameservers are managed by cloudflare. 

Comment: This limitation could be overcome in the future. 
The name server has to have an API through which Dns record can be added or deleted.

## createLEAccount
usage: ./createLEAccount /acnt=account /type=[prod|test] [/dbg]

The program requires the environmental variable LEDir pointing to a folder that will contain the account file.
The program creates an account with Let's Encrypt and stores the info in a yaml file (the account file).
The account file name is created form the account name "account" and "_prod.yaml" or "_test.yaml"

## checkLEAccount
usage: ./checkLEAccount /acnt=account /type=[prod|test] [/dbg]

This program checks whether the account file points to a valid Let's Encrypt account.

## createCerts
usage: ./createCerts /cr=<crlist> /account=<account> /dbg

program that creates a security certificate for https containg the zones (domains) listed in the cr file.

## cleanZones
usage: ./cleanZones /cr=<crlist> /account=<account> /dbg

program that checks and removes Dns challenge records 
