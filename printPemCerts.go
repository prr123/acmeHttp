// readPemCerts.go
// program that generates certificates from Lets encrypt using the DNS Challenge
// author: prr azul software
// date: 23 June 2023
// copyright 2023 prr, azulsoftware
//

package main

import (
	"log"
	"fmt"
	"os"
//	"strings"
//	"time"

	certLib "acme/acmeHttp/certHttpLib"
    util "github.com/prr123/utility/utilLib"
)


func main() {

	numarg := len(os.Args)

    flags:=[]string{"dbg","cert", "type"}

	useStr := "printPemCerts /cert='cert name' /type=prod|test [/dbg]"
	helpStr := "program that prints the content a Pem Cert File"

	if numarg > len(flags) +1 {
		fmt.Println("too many arguments in cl!")
		fmt.Println("usage: %s\n", useStr)
		os.Exit(-1)
	}

	if numarg> 1 && os.Args[1] == "help" {
		fmt.Printf("help: %s\n", helpStr)
		fmt.Printf("usage: %s\n", useStr)
		os.Exit(0)
	}


	flagMap, err := util.ParseFlags(os.Args, flags)
	if err != nil {log.Fatalf("util.ParseFlags: %v\n", err)}

	dbg := false
	_, ok := flagMap["dbg"]
	if ok {dbg = true}

	certNamVal, ok := flagMap["cert"]
	if ok {
		if certNamVal.(string) == "none" {log.Fatalf("error -- no string provided with /name flag!")}
	} else {
		log.Fatalf("error -- need cert flag and value\n")
	}
	certName := certNamVal.(string)
	log.Printf("cert Name: %s\n", certName)

    atypval, ok := flagMap["type"]
    if !ok {log.Fatalf("error -- /type flag not present!\n")}
    if atypval.(string) == "none" {log.Fatalf("error -- no type provided with /type flag!\n")}

    certObj, err := certLib.InitCertLib(dbg, atypval.(string))
    if err != nil {log.Fatalf("error -- InitCertLib: %v\n", err)}

    // log.Printf("info -- crFilbase:  %s\n", crFilbase)
    fmt.Println("************ input files ***********")
        fmt.Printf("info -- prod:       %t\n", certObj.Prod)
        fmt.Printf("info -- debug:      %t\n", dbg)
        if dbg {certObj.PrintCertObj()}
    fmt.Println("************ input files ***********")

	certFilnam := certObj.LeDir + "/certs/certTest" + certName + ".crt"
	if certObj.Prod {
		certFilnam = certObj.LeDir + "/certs/" + certName + ".crt"
	}
	certObj.CertFilnam = certFilnam

	_, err = os.Stat(certObj.CertFilnam)
	if err != nil {log.Fatalf("error -- cert file with name: %s does not exist: %v\n", certObj.CertFilnam, err)}

	log.Printf("info -- success locating cert file\n")

	err = certLib.ReadPemCerts(certObj.CertFilnam, certObj.Dbg)
	if err != nil {log.Fatalf("error -- ReadPemCerts: %v\n", err)}

	log.Printf("info -- success parsing Certs\n")
}
