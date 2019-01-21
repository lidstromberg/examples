package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"

	"net/http"

	"encoding/base64"

	auth "github.com/lidstromberg/auth"
	lbcf "github.com/lidstromberg/config"
	whtl "github.com/lidstromberg/whitelist"
	"golang.org/x/net/context"
)

var (
	urlbase = "https://{{YourAppengineServiceUrl}}.appspot.com/%s"
	//urlbase = "http://localhost:8080/%s"
)

func Test_SetWhitelist(t *testing.T) {
	ctx := context.Background()

	bc := lbcf.NewConfig(ctx)

	wl, err := whtl.NewWhlMgr(ctx, bc)

	if err != nil {
		t.Fatal(err)
	}

	err = wl.Set(ctx, "::1")

	if err != nil {
		t.Fatal(err)
	}
}
func Test_Register(t *testing.T) {
	url1 := fmt.Sprintf(urlbase, "auth/api/v1/global/register")

	//create a http client
	cli := &http.Client{}

	//set the login payload
	payload := []byte(`{"email":"test@here.com","password":"pass999"}`)

	//create the request
	rq, err := http.NewRequest("POST", url1, bytes.NewBuffer(payload))
	rq.Header.Set("Content-Type", "application/json")

	//run the request
	rsp, err := cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	//report the headers and get the body
	//t.Logf("response Status: %s", rsp.Status)
	//t.Logf("response Headers: %s", rsp.Header)

	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a RegisterResult
	res1 := &RegisterResult{Header: &HdlError{}}
	err = json.Unmarshal(body, res1)
	if err != nil {
		t.Fatal(err)
	}

	if res1.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res1.Header.Error)
	}

	t.Logf("Register result confirmtoken: %s", res1.ConfirmToken)
	t.Logf("Register user account: %s", res1.UserAccountID)
}
func Test_ConfirmRegistration(t *testing.T) {
	url1 := fmt.Sprintf(urlbase, "auth/api/v1/global/register")
	url2 := fmt.Sprintf(urlbase, "auth/api/v1/global/confirmer/%s")

	//create a http client
	cli := &http.Client{}

	//set the login payload
	payload := []byte(`{"email":"testconfirm@here.com","password":"pass999"}`)

	//create the request
	rq, err := http.NewRequest("POST", url1, bytes.NewBuffer(payload))
	rq.Header.Set("Content-Type", "application/json")

	//run the request
	rsp, err := cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a Result
	res1 := &RegisterResult{Header: &HdlError{}}
	err = json.Unmarshal(body, res1)
	if err != nil {
		t.Fatal(err)
	}

	if res1.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res1.Header.Error)
	}

	//new request for the profile
	newurl := fmt.Sprintf(url2, res1.ConfirmToken)
	rq, err = http.NewRequest("GET", newurl, nil)

	//run the new request
	rsp, err = cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	body, err = ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a result
	res2 := &ConfirmationResult{Header: &HdlError{}}
	err = json.Unmarshal(body, res2)
	if err != nil {
		t.Fatal(err)
	}

	if res2.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res2.Header.Error)
	}

	t.Logf("ConfirmRegistration link result: %s", res2.RedirectLink)
}
func Test_Login(t *testing.T) {
	url1 := fmt.Sprintf(urlbase, "auth/api/v1/global/login")

	//create a http client
	cli := &http.Client{}

	//set the login payload
	payload := []byte(`{"email":"test@here.com","password":"pass999"}`)

	//create the request
	rq, err := http.NewRequest("POST", url1, bytes.NewBuffer(payload))
	rq.Header.Set("Content-Type", "application/json")

	//run the request
	rsp, err := cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a Result
	res1 := &LoginResult{Header: &HdlError{StatusID: http.StatusOK}, Token: &Token{}}
	err = json.Unmarshal(body, res1)
	if err != nil {
		t.Fatal(err)
	}

	if res1.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res1.Header.Error)
	}

	if res1.LoginID != "" {
		t.Fatal("loginid was returned.. this is an otp account")
	}

	t.Logf("Login session result: %s", res1.Token.SessionID)
}
func Test_GetLoginProfile(t *testing.T) {
	url1 := fmt.Sprintf(urlbase, "auth/api/v1/global/login")
	url2 := fmt.Sprintf(urlbase, "auth/api/v1/profile/detail")

	//create a http client
	cli := &http.Client{}

	//set the login payload
	payload := []byte(`{"email":"test@here.com","password":"pass999"}`)

	//create the request
	rq, err := http.NewRequest("POST", url1, bytes.NewBuffer(payload))
	rq.Header.Set("Content-Type", "application/json")

	//run the request
	rsp, err := cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a token
	res1 := &TokenResult{Header: &HdlError{}, Token: &Token{}}
	err = json.Unmarshal(body, res1)
	if err != nil {
		t.Fatal(err)
	}

	//check the action status
	if res1.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res1.Header.Error)
	}

	//reset the request to get the account
	rq, err = http.NewRequest("POST", url2, nil)
	rq.Header.Set("Content-Type", "application/json")

	//set the authorization header
	br := fmt.Sprintf("Bearer %s", res1.Token.SessionID)
	rq.Header.Set("Authorization", br)

	//run the new request
	rsp, err = cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	body, err = ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a result
	res2 := &LoginProfileResult{Header: &HdlError{}, Token: &Token{}, Account: &auth.UserAccount{}}
	err = json.Unmarshal(body, res2)
	if err != nil {
		t.Fatal(err)
	}

	//check the action status
	if res2.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res2.Header.Error)
	}

	t.Logf("Account response: %v", res2.Account)
	t.Logf("Token response: %v", res2.Token)
}
func Test_SaveProfile(t *testing.T) {
	url1 := fmt.Sprintf(urlbase, "auth/api/v1/global/login")
	url2 := fmt.Sprintf(urlbase, "auth/api/v1/profile/detail")
	url3 := fmt.Sprintf(urlbase, "auth/api/v1/profile/store")

	//create a http client
	cli := &http.Client{}

	//set the login payload
	payload := []byte(`{"email":"test@here.com","password":"pass999"}`)

	//create the request
	rq, err := http.NewRequest("POST", url1, bytes.NewBuffer(payload))
	rq.Header.Set("Content-Type", "application/json")

	//run the request
	rsp, err := cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a token
	res1 := &TokenResult{Header: &HdlError{}, Token: &Token{}}
	err = json.Unmarshal(body, res1)
	if err != nil {
		t.Fatal(err)
	}

	//check the action status
	if res1.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res1.Header.Error)
	}

	//reset the request to get the account
	rq, err = http.NewRequest("POST", url2, nil)
	rq.Header.Set("Content-Type", "application/json")

	//set the authorization header
	br := fmt.Sprintf("Bearer %s", res1.Token.SessionID)
	rq.Header.Set("Authorization", br)

	//run the new request
	rsp, err = cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	body, err = ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a result
	res2 := &LoginProfileResult{Token: &Token{}, Account: &auth.UserAccount{}}
	err = json.Unmarshal(body, res2)
	if err != nil {
		t.Fatal(err)
	}

	//check the action status
	if res2.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res2.Header.Error)
	}

	t.Logf("Account response: %v", res2.Account)
	t.Logf("Token response: %v", res2.Token)

	//modify and send the account back
	res2.Account.PhoneNumber = "987"
	dat, err := json.Marshal(res2.Account)
	if err != nil {
		t.Fatal(err)
	}

	//reset the request to update the account
	rq, err = http.NewRequest("POST", url3, bytes.NewBuffer(dat))
	rq.Header.Set("Content-Type", "application/json")

	//set the authorization header
	br = fmt.Sprintf("Bearer %s", res2.Token.SessionID)
	rq.Header.Set("Authorization", br)

	//run the new request
	rsp, err = cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	body, err = ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a result
	res3 := &BoolResult{Header: &HdlError{}, Token: &Token{}}
	err = json.Unmarshal(body, res3)
	if err != nil {
		t.Fatal(err)
	}

	//check the action status
	if res3.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res3.Header.Error)
	}

	t.Logf("SaveProfile result: %t", res3.Result)
}
func Test_SavePassword(t *testing.T) {
	url1 := fmt.Sprintf(urlbase, "auth/api/v1/global/login")
	url2 := fmt.Sprintf(urlbase, "auth/api/v1/profile/detail")
	url3 := fmt.Sprintf(urlbase, "auth/api/v1/profile/credential")

	//create a http client
	cli := &http.Client{}

	//set the login payload
	payload := []byte(`{"email":"test@here.com","password":"pass999"}`)

	//create the request
	rq, err := http.NewRequest("POST", url1, bytes.NewBuffer(payload))
	rq.Header.Set("Content-Type", "application/json")

	//run the request
	rsp, err := cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a Result
	res1 := &TokenResult{Token: &Token{}, Header: &HdlError{}}
	err = json.Unmarshal(body, res1)
	if err != nil {
		t.Fatal(err)
	}

	if res1.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res1.Header.Error)
	}

	//reset the request to get the account
	rq, err = http.NewRequest("POST", url2, nil)
	rq.Header.Set("Content-Type", "application/json")

	//set the authorization header
	br := fmt.Sprintf("Bearer %s", res1.Token.SessionID)
	rq.Header.Set("Authorization", br)

	//run the new request
	rsp, err = cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	body, err = ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a result
	res2 := &LoginProfileResult{Header: &HdlError{}, Token: &Token{}, Account: &auth.UserAccount{}}
	err = json.Unmarshal(body, res2)
	if err != nil {
		t.Fatal(err)
	}

	//check the action status
	if res2.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res2.Header.Error)
	}

	t.Logf("Account response: %v", res2.Account)

	//set the password change payload
	tmpl := `{"useraccountid": "%s","password":"pass111"}`
	tmpl = fmt.Sprintf(tmpl, res2.Account.UserAccountID)
	payload = []byte(tmpl)

	//reset the request to update the password
	rq, err = http.NewRequest("POST", url3, bytes.NewBuffer(payload))
	rq.Header.Set("Content-Type", "application/json")

	//set the authorization header
	br = fmt.Sprintf("Bearer %s", res2.Token.SessionID)
	rq.Header.Set("Authorization", br)

	//run the new request
	rsp, err = cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	body, err = ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a result
	res3 := &BoolResult{Header: &HdlError{}, Token: &Token{}}
	err = json.Unmarshal(body, res3)
	if err != nil {
		t.Fatal(err)
	}

	//check the action status
	if res3.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res3.Header.Error)
	}

	t.Logf("SaveProfile result: %t", res3.Result)
}
func Test_RequestReset(t *testing.T) {
	url1 := fmt.Sprintf(urlbase, "auth/api/v1/global/reset/start")

	//create a http client
	cli := &http.Client{}

	//set the login payload
	payload := []byte(`{"email":"test@here.com"}`)

	//create the request
	rq, err := http.NewRequest("POST", url1, bytes.NewBuffer(payload))
	rq.Header.Set("Content-Type", "application/json")

	//run the request
	rsp, err := cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a Result
	res1 := &ConfirmTokenResult{Header: &HdlError{}}
	err = json.Unmarshal(body, res1)
	if err != nil {
		t.Fatal(err)
	}

	if res1.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res1.Header.Error)
	}

	t.Logf("RequestReset result: %s", res1.ConfirmToken)
}
func Test_FinishReset(t *testing.T) {
	url1 := fmt.Sprintf(urlbase, "auth/api/v1/global/reset/start")
	url2 := fmt.Sprintf(urlbase, "auth/api/v1/global/reset/finish")

	//create a http client
	cli := &http.Client{}

	//set the login payload
	payload := []byte(`{"email":"test@here.com"}`)

	//create the request
	rq, err := http.NewRequest("POST", url1, bytes.NewBuffer(payload))
	rq.Header.Set("Content-Type", "application/json")

	//run the request
	rsp, err := cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a result
	res1 := &ConfirmTokenResult{Header: &HdlError{}}
	err = json.Unmarshal(body, res1)
	if err != nil {
		t.Fatal(err)
	}

	if res1.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res1.Header.Error)
	}

	t.Logf("RequestReset result: %s", res1.ConfirmToken)

	//set the login payload
	pl := `{"confirmtoken":"%s", "password":"pass999"}`
	payload = []byte(fmt.Sprintf(pl, res1.ConfirmToken))

	//reset the request to get the account
	rq, err = http.NewRequest("POST", url2, bytes.NewBuffer(payload))
	rq.Header.Set("Content-Type", "application/json")

	//run the new request
	rsp, err = cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	body, err = ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a result
	res2 := &ConfirmationResult{Header: &HdlError{}}
	err = json.Unmarshal(body, res2)
	if err != nil {
		t.Fatal(err)
	}

	if res2.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res2.Header.Error)
	}

	t.Logf("response link: %s", res2.RedirectLink)
}
func Test_ToggleTwoFAOn(t *testing.T) {
	url1 := fmt.Sprintf(urlbase, "auth/api/v1/global/login")
	url2 := fmt.Sprintf(urlbase, "auth/api/v1/profile/detail")
	url3 := fmt.Sprintf(urlbase, "auth/api/v1/profile/tfa")

	//create a http client
	cli := &http.Client{}

	//set the login payload
	payload := []byte(`{"email":"test@here.com","password":"pass999"}`)

	//create the request
	rq, err := http.NewRequest("POST", url1, bytes.NewBuffer(payload))
	rq.Header.Set("Content-Type", "application/json")

	//run the request
	rsp, err := cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a token
	res1 := &TokenResult{Header: &HdlError{}, Token: &Token{}}
	err = json.Unmarshal(body, res1)
	if err != nil {
		t.Fatal(err)
	}

	//check the action status
	if res1.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res1.Header.Error)
	}

	//reset the request to get the account
	rq, err = http.NewRequest("POST", url2, nil)
	rq.Header.Set("Content-Type", "application/json")

	//set the authorization header
	br := fmt.Sprintf("Bearer %s", res1.Token.SessionID)
	rq.Header.Set("Authorization", br)

	//run the new request
	rsp, err = cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	body, err = ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a result
	res2 := &LoginProfileResult{Token: &Token{}, Account: &auth.UserAccount{}}
	err = json.Unmarshal(body, res2)
	if err != nil {
		t.Fatal(err)
	}

	//check the action status
	if res2.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res2.Header.Error)
	}

	t.Logf("Account response: %v", res2.Account)
	t.Logf("Token response: %v", res2.Token)

	//set the password change payload
	tmpl := `{"useraccountid": "%s", "otp": %s}`
	tmpl = fmt.Sprintf(tmpl, res2.Account.UserAccountID, "true")
	payload = []byte(tmpl)

	//reset the request to update the password
	rq, err = http.NewRequest("POST", url3, bytes.NewBuffer(payload))
	rq.Header.Set("Content-Type", "application/json")

	//set the authorization header
	br = fmt.Sprintf("Bearer %s", res2.Token.SessionID)
	rq.Header.Set("Authorization", br)

	//run the new request
	rsp, err = cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	body, err = ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a result
	res3 := &AccountOtpResult{Header: &HdlError{}, Token: &Token{}, Otp: &auth.ToggleOtpResult{}}
	err = json.Unmarshal(body, res3)
	if err != nil {
		t.Fatal(err)
	}

	//check the action status
	if res3.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res3.Header.Error)
	}

	//decode the qr
	qr, err := base64.StdEncoding.DecodeString(res3.Otp.Qr)
	if err != nil {
		t.Fatal(err)
	}

	//write to file
	ioutil.WriteFile("qr-code.png", qr, 0644)

	t.Logf("SaveProfile qr result: %s", res3.Otp.Qr)
}
func Test_LoginOtp(t *testing.T) {
	url1 := fmt.Sprintf(urlbase, "auth/api/v1/global/login")
	url2 := fmt.Sprintf(urlbase, "auth/api/v1/global/otp")
	otpval := "670158"

	//create a http client
	cli := &http.Client{}

	//set the login payload
	payload := []byte(`{"email":"test@here.com","password":"pass999"}`)

	//create the request
	rq, err := http.NewRequest("POST", url1, bytes.NewBuffer(payload))
	rq.Header.Set("Content-Type", "application/json")

	//run the request
	rsp, err := cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a Result
	res1 := &LoginResult{Header: &HdlError{StatusID: http.StatusOK}, Token: &Token{}}
	err = json.Unmarshal(body, res1)
	if err != nil {
		t.Fatal(err)
	}

	if res1.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res1.Header.Error)
	}

	//check that we have a loginid
	if res1.LoginID == "" {
		t.Fatal("loginid was not returned.. it should be here now")
	}

	//set the password change payload
	tmpl := `{"loginid": "%s", "otp": "%s"}`
	tmpl = fmt.Sprintf(tmpl, res1.LoginID, otpval)
	payload = []byte(tmpl)

	//reset the request to get the account
	rq, err = http.NewRequest("POST", url2, bytes.NewBuffer(payload))
	rq.Header.Set("Content-Type", "application/json")

	//run the new request
	rsp, err = cli.Do(rq)
	if err != nil {
		t.Fatal(err)
	}

	//check if the op is forbidden
	if rsp.Status == "403 Forbidden" {
		t.Fatal("Operation was forbidden")
	}

	body, err = ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()

	//unmarshall the response into a result
	res2 := &LoginResult{Header: &HdlError{}, Token: &Token{}}
	err = json.Unmarshal(body, res2)
	if err != nil {
		t.Fatal(err)
	}

	//check the action status
	if res2.Header.StatusID != http.StatusOK {
		t.Fatalf("failure in action: %s", res2.Header.Error)
	}

	//check that we no longer have a loginid
	if res2.LoginID != "" {
		t.Fatal("loginid was returned.. it shouldn't be here now")
	}

	t.Logf("Token response: %s", res2.Token.SessionID)
}
