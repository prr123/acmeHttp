// createHttpCerts.go
// program that generates certificates from Lets encrypt using the DNS Challenge
// author: prr azul software
// date: 29 Dec 2024
// copyright 2024 prr, azulsoftware
//

package main

import (
	"log"
	"fmt"
	"os"
//	"time"
	"strings"
//	"context"

	certLib "acme/acmeHttp/certHttpLib"
    util "github.com/prr123/utility/utilLib"
)


func main() {

	numArgs := len(os.Args)

    flags:=[]string{"dbg","cr","type"}

	useStr := "./createHttpCerts /cr=<csrname> /type=prod|test [/dbg]"
	helpStr := "program that creates one certificate for all domains listed in the file csrname.cr"

	if numArgs > len(flags) + 1 {
		fmt.Println("too many arguments in cl!")
		fmt.Println("usage: %s\n", useStr)
		os.Exit(-1)
	}

	if numArgs == 1 || (numArgs>1 && os.Args[1] == "help") {
		fmt.Printf("help: %s\n", helpStr)
		fmt.Printf("usage is: %s\n", useStr)
		os.Exit(-1)
	}

	flagMap, err := util.ParseFlags(os.Args, flags)
	if err != nil {log.Fatalf("error -- util.ParseFlags: %v\n", err)}

	dbg := false
	_, ok := flagMap["dbg"]
	if ok {dbg = true}

    crval, ok := flagMap["cr"]
    if !ok {log.Fatalf("error -- /cr flag not present!\n")}
    if crval.(string) == "none" {log.Fatalf("error -- no cr file provided with /cr flag!\n")}
    if idx := strings.Index(crval.(string), "."); idx > -1 {
        log.Fatalf("error -- cr name has an extension!\n")
    }
    if idx := strings.Index(crval.(string), "_"); idx == -1 {
        log.Fatalf("error -- cr name has no tld!\n")
    }

    // determine whether account file is production (prod) or test    acntval, ok := flagMap["account"]
//    acntval, ok := flagMap["account"]
//    if !ok {log.Fatalf("error -- /account flag not present!\n")}
//    if acntval.(string) == "none" {log.Fatalf("error -- no name provided with /account flag!\n")}

    atypval, ok := flagMap["type"]
    if !ok {log.Fatalf("error -- /type flag not present!\n")}
    if atypval.(string) == "none" {log.Fatalf("error -- no type provided with /type flag!\n")}

	// may refactor the certObj
	certObj, err := certLib.InitCertLib(dbg, atypval.(string))
	if err != nil {log.Fatalf("error -- InitCertLib: %v\n", err)}

    CrList, err := certObj.ReadCrFile(crval.(string))
    if err != nil {log.Fatalf("error -- ReadCrFile: %v\n", err)}

    // list of inputs
	// log.Printf("info -- crFilbase:  %s\n", crFilbase)
	fmt.Println("************ input files ***********")
    	fmt.Printf("info -- prod:       %t\n", certObj.Prod)
		fmt.Printf("info -- debug:      %t\n", dbg)
		if dbg {certLib.PrintCrList(CrList)}
    	if dbg {certObj.PrintCertObj()}
	fmt.Println("************ input files ***********")


	// generate acme client and retrieve let's encrypt account
    err = certObj.GetAcmeClient()
    if err != nil {log.Fatalf("error -- certobj.GetAcmeClient: %v\n", err)}

    if dbg {certLib.PrintClient(certObj.Client)}
    if dbg {certLib.PrintAccount(certObj.LEAccount)}


	// get authorisation order from Let's Encrypt
	order, err := certObj.GetAuthOrder(CrList)
	if err != nil {log.Fatalf("error -- GetAuthOrder: %v\n", err)}

	if dbg {certLib.PrintOrder(order)}
	log.Printf("info -- received Authorization Order!\n")

	// update CRList with authentication info from LE
	// create Dns challenge records on cloudflare's name servers
	CrList, err = certObj.GetAuthFromOrder(CrList, order)
	if err != nil {log.Fatalf("error -- GetAuthAndToken: %v\n", err)}

	log.Printf("info -- created all https challenge records!")

	// create server to receive challenge
	// we can implement different challenge methods


	// submit that challenge is ready
	err = certObj.SubmitChallenge(CrList)
	if err != nil {log.Fatalf("error -- Submit Challenge: %v\n", err)}
	log.Printf("info -- Challenge accepted!\n")

	ordUrl := order.URI

	// activate server and shutdown server after challenge was received
	err = certLib.StartHttp(&(CrList[0]), 15)
	if err !=nil {log.Fatalf("error -- starting http: %v\n", err)}

	acmeOrder, err := certObj.GetOrderAndWait(ordUrl)
	if err !=nil {log.Fatalf("error -- WaitGetOrder: %v\n", err)}
	log.Printf("info -- received order\n")
    if certObj.Dbg {certLib.PrintOrder(acmeOrder)}

	err = certObj.CreateCerts(&(CrList[0]))
	if err != nil { log.Fatalf("error -- CreateCerts: %v\n", err)}

	log.Printf("info -- success createCerts\n")
    if certObj.Dbg {certLib.PrintOrder(acmeOrder)}
}

