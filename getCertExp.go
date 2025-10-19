// getCertExp.go
// program reads Pem Certs and displays the expiration
// author: prr azul software
// date: 10 Feb 2025
// copyright 2025 prr, azulsoftware
//
// 19/10 changes
// - fix default directory
// -- fix cli to display help if no arg is provided

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

    flags:=[]string{"dbg","domain"}

	useStr := os.Args[0] + " /domain='domain name' [/dbg]"
	helpStr := "program that prints the expirary of a Pem Cert File"

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

	if numarg == 1 {
		fmt.Printf("help: %s\n", helpStr)
		fmt.Printf("usage: %s\n", useStr)
		os.Exit(0)
	}

	flagMap, err := util.ParseFlags(os.Args, flags)
	if err != nil {log.Fatalf("util.ParseFlags: %v\n", err)}

	dbg := false
	_, ok := flagMap["dbg"]
	if ok {dbg = true}

	dNamVal, ok := flagMap["domain"]
	if ok {
		if dNamVal.(string) == "none" {log.Fatalf("error -- no string provided with /domain flag!")}
	} else {
		log.Fatalf("error -- need cert flag and value\n")
	}
	dName := dNamVal.(string)
	log.Printf("domain: %s\n", dName)

	dNamSl := []byte(dName)
	for i:=0; i< len(dName); i++ {
		if dNamSl[i] == '.' {dNamSl[i] = '_'}
	}

	certObj, err := certLib.InitCertLib(dbg, "prod")
	if err != nil {log.Fatalf("error -- InitCertLib: %v\n", err)}

	certObj.CertFilnam = "/home/peter/cloud/domains/" + dName + "/devops/" + string(dNamSl) + ".crt"

	_, err = os.Stat(certObj.CertFilnam)
	if err != nil {log.Fatalf("error -- cert file with name: %s does not exist: %v\n", certObj.CertFilnam, err)}

	log.Printf("info -- success locating cert file\n")

//	err = certLib.ReadPemCerts(certObj.CertFilnam, certObj.Dbg)
//	if err != nil {log.Fatalf("error -- ReadPemCerts: %v\n", err)}

	certinfo, err := certLib.GetCertsExp(certObj.CertFilnam, certObj.Dbg)
	if err != nil {log.Fatalf("error -- GetCertsExp: %v\n", err)}

	fmt.Printf("******** certs: %d ****\n", len(certinfo))
	log.Printf("info -- success parsing Certs\n")
}
