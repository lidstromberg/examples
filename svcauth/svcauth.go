package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	auth "github.com/lidstromberg/auth"
	lbcf "github.com/lidstromberg/config"
	kp "github.com/lidstromberg/keypair"
	lblog "github.com/lidstromberg/log"
	gt "github.com/lidstromberg/requestgateway"
	sess "github.com/lidstromberg/session"

	//pprof is blank import http profiler
	_ "net/http/pprof"

	"github.com/gorilla/mux"
	sendgrid "github.com/sendgrid/sendgrid-go"
	"github.com/urfave/negroni"
	"golang.org/x/net/context"
)

//SvMgr is the implementation
type SvMgr struct {
	bc      lbcf.ConfigSetting
	sm      sess.SessProvider
	cr      auth.AuthCore
	gt      *gt.GtwyMgr
	Mx      *mux.Router
	appname string
}

//IsApproved checks that the requester is authorised
func (sv *SvMgr) IsApproved(w http.ResponseWriter, r *http.Request, nx http.HandlerFunc) {
	// prepare the json writer for outgoing messages
	jswr := json.NewEncoder(w)

	ctx := r.Context()

	//X-Forwarded-For is always supplied by appengine, and the first element is usually the original IP
	ra := strings.Split(r.Header.Get("X-Forwarded-For"), ",")

	//if we can't determine who it is then forbidden
	if len(ra) == 0 {
		lblog.LogEvent("SvMgr", "IsApproved", "error", ErrUnknownReq.Error())

		w.WriteHeader(http.StatusForbidden)
		if errJ := jswr.Encode(&HdlError{StatusID: http.StatusForbidden, Error: ErrUnknownReq.Error()}); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//check each of the ip addresses to see if one is approved
	var chk bool
	for _, item := range ra {
		//log the ip
		lblog.LogEvent("SvMgr", "IsApproved", "info", item)

		//check if the address is approved
		chk2, err := sv.gt.IsPermitted(ctx, item)

		//if error then report
		if err != nil {
			lblog.LogEvent("SvMgr", "IsApproved-IsPermitted", "error", err.Error())

			w.WriteHeader(http.StatusInternalServerError)
			if errJ := jswr.Encode(&HdlError{StatusID: http.StatusInternalServerError, Error: err.Error()}); errJ != nil {
				http.Error(w, errJ.Error(), http.StatusInternalServerError)
			}
			return
		}

		//if the address was approved then exit
		if chk2 {
			chk = chk2
			break
		}
	}

	//if this isn't approved then return forbidden
	if !chk {
		lblog.LogEvent("SvMgr", "IsApproved-IsPermitted", "error", ErrForbiddenReq.Error())

		w.WriteHeader(http.StatusForbidden)
		if errJ := jswr.Encode(&HdlError{StatusID: http.StatusForbidden, Error: ErrForbiddenReq.Error()}); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//then we continue (or we have redirected because the IP is not approved)
	nx(w, r)
}

//HasAuthorisation checks that the authorization header exists
func (sv *SvMgr) HasAuthorisation(w http.ResponseWriter, r *http.Request, nx http.HandlerFunc) {
	// prepare the json writer for outgoing messages
	jswr := json.NewEncoder(w)

	bearerToken := strings.Split(r.Header.Get(EnvRqAuthHdr), " ")

	if len(bearerToken) != 2 {
		lblog.LogEvent("SvMgr", "HasAuthorisation-GetAuthHeader", "error", ErrSessionNotExist.Error())

		w.WriteHeader(http.StatusInternalServerError)
		if errJ := jswr.Encode(&HdlError{StatusID: http.StatusInternalServerError, Error: ErrSessionNotExist.Error()}); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//add the authorization metadata
	ctx := r.Context()
	ctx = context.WithValue(ctx, EnvCtxKey, bearerToken[1])

	//apply the context to the request
	r = r.WithContext(ctx)

	//then continue
	nx(w, r)
}

//Register registers a new account
func (sv *SvMgr) Register(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", EnvDomain)
	w.Header().Add("Content-Type", "application/json; charset=UTF-8")

	//handle OPTIONS request
	if r.Method == "OPTIONS" {
		w.Header().Add("Access-Control-Allow-Methods", "POST")
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type,x-lidstromberg-api")
		return
	}
	// prepare the json writer for outgoing messages
	jswr := json.NewEncoder(w)

	//prepare result
	res := &RegisterResult{Header: &HdlError{StatusID: http.StatusOK}}

	//requires new context
	ctx := r.Context()

	ac := &auth.UserAccountCandidate{}
	err := json.NewDecoder(r.Body).Decode(ac)
	if err != nil {
		lblog.LogEvent("SvMgr", "Register", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusUnprocessableEntity
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//register the account
	rgres := sv.cr.Register(ctx, ac, sv.appname)

	//return the error
	if rgres.Check.Error != nil {
		lblog.LogEvent("SvMgr", "Register", "error", rgres.Check.Error.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusInternalServerError
		res.Header.Error = rgres.Check.Error.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//raise an error if the token wasn't created
	if rgres.ConfirmToken == "" {
		lblog.LogEvent("SvMgr", "Register", "error", ErrConfTokenEmpty.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusInternalServerError
		res.Header.Error = ErrConfTokenEmpty.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//otherwise report successful completion
	w.WriteHeader(http.StatusOK)
	res.ConfirmToken = rgres.ConfirmToken
	res.UserAccountID = rgres.UserAccountID

	if err = jswr.Encode(res); err != nil {
		lblog.LogEvent("SvMgr", "Register", "error", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	lblog.LogEvent("SvMgr", "Register", "info", "complete")
}

//ConfirmReg accepts a registration token to complete the registration cycle
func (sv *SvMgr) ConfirmReg(w http.ResponseWriter, r *http.Request) {
	// prepare the json writer for outgoing messages
	jswr := json.NewEncoder(w)

	//prepare result
	res := &ConfirmationResult{Header: &HdlError{StatusID: http.StatusOK}}

	//requires new context
	ctx := r.Context()
	tok := mux.Vars(r)["token"]

	//check that the token was present
	if tok == "" {
		lblog.LogEvent("SvMgr", "ConfirmReg", "error", ErrRqTokenEmpty.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusBadRequest
		res.Header.Error = ErrRqTokenEmpty.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}
	lblog.LogEvent("SvMgr", "ConfirmReg", "conftoken", tok)

	//attempt to complete the registration
	confres, err := sv.cr.FinishAccountConfirmation(ctx, tok)

	//return the error
	if err != nil {
		lblog.LogEvent("SvMgr", "ConfirmReg", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusInternalServerError
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//otherwise report successful completion
	w.WriteHeader(http.StatusOK)
	res.RedirectLink = confres.RedirectLink

	if err = jswr.Encode(res); err != nil {
		lblog.LogEvent("SvMgr", "ConfirmReg", "error", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	lblog.LogEvent("SvMgr", "ConfirmReg", "info", "complete")
}

//Login logs in an existing account
func (sv *SvMgr) Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", EnvDomain)
	w.Header().Add("Content-Type", "application/json; charset=UTF-8")

	//handle OPTIONS request
	if r.Method == "OPTIONS" {
		w.Header().Add("Access-Control-Allow-Methods", "POST")
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type,x-lidstromberg-api")
		return
	}
	// prepare the json writer for outgoing messages
	jswr := json.NewEncoder(w)

	//prepare result
	res := &LoginResult{Header: &HdlError{StatusID: http.StatusOK}, Token: &Token{}}

	//requires new context
	ctx := r.Context()

	ac := &auth.UserAccountCandidate{}
	err := json.NewDecoder(r.Body).Decode(ac)
	if err != nil {
		lblog.LogEvent("SvMgr", "Login", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusUnprocessableEntity
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//attempt the login
	lgres := sv.cr.Login(ctx, ac, sv.appname)

	//return the error
	if lgres.Check.Error != nil {
		lblog.LogEvent("SvMgr", "Login", "error", lgres.Check.Error.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusInternalServerError
		res.Header.Error = lgres.Check.Error.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//if this isn't a 2fa account then
	if !lgres.IsTwoFactor {
		//activate the login candidate
		shdr, err := sv.cr.ActivateLoginCandidate(ctx, lgres.LoginID)
		if err != nil {
			lblog.LogEvent("SvMgr", "Login-ActivateLC", "error", err.Error())

			w.WriteHeader(http.StatusOK)
			res.Header.StatusID = http.StatusInternalServerError
			res.Header.Error = err.Error()

			if errJ := jswr.Encode(res); errJ != nil {
				http.Error(w, errJ.Error(), http.StatusInternalServerError)
			}
			return
		}

		//and get the jwt
		sessid, err := sv.sm.NewSession(ctx, shdr)
		if err != nil {
			lblog.LogEvent("SvMgr", "Login-NewSession", "error", err.Error())

			w.WriteHeader(http.StatusOK)
			res.Header.StatusID = http.StatusInternalServerError
			res.Header.Error = err.Error()

			if errJ := jswr.Encode(res); errJ != nil {
				http.Error(w, errJ.Error(), http.StatusInternalServerError)
			}
			return
		}

		res.Token.SessionID = sessid
	} else {
		res.LoginID = lgres.LoginID
	}

	//otherwise report successful completion
	w.WriteHeader(http.StatusOK)
	if err = jswr.Encode(res); err != nil {
		lblog.LogEvent("SvMgr", "Login", "error", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	lblog.LogEvent("SvMgr", "Login", "info", "complete")
}

//GetLoginProfile returns the user account profile
func (sv *SvMgr) GetLoginProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", EnvDomain)
	w.Header().Add("Content-Type", "application/json; charset=UTF-8")

	//handle OPTIONS request
	if r.Method == "OPTIONS" {
		w.Header().Add("Access-Control-Allow-Methods", "POST")
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type,x-lidstromberg-api")
		return
	}
	// prepare the json writer for outgoing messages
	jswr := json.NewEncoder(w)

	//prepare result
	res := &LoginProfileResult{Header: &HdlError{StatusID: http.StatusOK}, Token: &Token{}}

	//this is wrapped by middleware, authorization is in the metdata
	ctx := r.Context()

	//get the jwt
	sessid := ctx.Value(EnvCtxKey).(string)

	if sessid == "" {
		lblog.LogEvent("SvMgr", "GetLoginProfile", "error", ErrSessionNotExist.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusForbidden
		res.Header.Error = ErrSessionNotExist.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//check that the session is valid
	_, err := sv.sm.IsSessionValid(ctx, sessid)

	if err != nil {
		lblog.LogEvent("SvMgr", "GetLoginProfile", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusForbidden
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//set a context timeout
	ctx, cancel := context.WithTimeout(ctx, EnvCtxTimeout)
	defer cancel()

	//if the token was valid then start the refresh request
	rfchn := sv.sm.RefreshSession(ctx, sessid)
	defer sess.DrainFn(rfchn)

	aid, err := sv.sm.GetJwtClaimElement(ctx, sessid, sess.ConstJwtAccID)
	if err != nil {
		lblog.LogEvent("SvMgr", "GetLoginProfile", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusUnprocessableEntity
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//get the user profile
	uacc, err := sv.cr.GetLoginProfile(ctx, aid.(string), true)
	if err != nil {
		lblog.LogEvent("SvMgr", "GetLoginProfile", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusInternalServerError
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//get the refreshed session
	var wg sync.WaitGroup
	wg.Add(1)
	newsess := sess.PollFn(ctx, &wg, sessid, rfchn)
	wg.Wait()

	//otherwise report successful completion
	w.WriteHeader(http.StatusOK)
	res.Token.SessionID = newsess
	res.Account = uacc

	if err = jswr.Encode(res); err != nil {
		lblog.LogEvent("SvMgr", "GetLoginProfile", "error", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	lblog.LogEvent("SvMgr", "GetLoginProfile", "info", "complete")
}

//SaveProfile saves a subset of user account details back to the store
func (sv *SvMgr) SaveProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", EnvDomain)
	w.Header().Add("Content-Type", "application/json; charset=UTF-8")

	//handle OPTIONS request
	if r.Method == "OPTIONS" {
		w.Header().Add("Access-Control-Allow-Methods", "POST")
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type,x-lidstromberg-api")
		return
	}
	// prepare the json writer for outgoing messages
	jswr := json.NewEncoder(w)

	//prepare result
	res := &BoolResult{Header: &HdlError{StatusID: http.StatusOK}, Token: &Token{}}

	//this is wrapped by middleware, authorization is in the metdata
	ctx := r.Context()

	//get the jwt
	sessid := ctx.Value(EnvCtxKey).(string)

	if sessid == "" {
		lblog.LogEvent("SvMgr", "SaveProfile", "error", ErrSessionNotExist.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusForbidden
		res.Header.Error = ErrSessionNotExist.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//check that the session is valid
	_, err := sv.sm.IsSessionValid(ctx, sessid)

	if err != nil {
		lblog.LogEvent("SvMgr", "SaveProfile", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusForbidden
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//set a context timeout
	ctx, cancel := context.WithTimeout(ctx, EnvCtxTimeout)
	defer cancel()

	//if the token was valid then start the refresh request
	rfchn := sv.sm.RefreshSession(ctx, sessid)
	defer sess.DrainFn(rfchn)

	//get the payload
	ac := &UpdateableUserAccount{}
	err = json.NewDecoder(r.Body).Decode(ac)
	if err != nil {
		lblog.LogEvent("SvMgr", "SaveProfile", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusUnprocessableEntity
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//get the user profile
	uacc, err := sv.cr.GetLoginProfile(ctx, ac.UserAccountID, true)

	//return the error
	if err != nil {
		lblog.LogEvent("SvMgr", "SaveProfile", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusInternalServerError
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//remap the updatable entries (none of the others should be updatable)
	uacc.Email = ac.Email
	uacc.PhoneNumber = ac.PhoneNumber

	//attempt to save the account
	_, err = sv.cr.SaveAccount(ctx, uacc)

	//return the error
	if err != nil {
		lblog.LogEvent("SvMgr", "SaveProfile", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusInternalServerError
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//get the refreshed session
	var wg sync.WaitGroup
	wg.Add(1)
	newsess := sess.PollFn(ctx, &wg, sessid, rfchn)
	wg.Wait()

	//otherwise report successful completion
	w.WriteHeader(http.StatusOK)
	res.Result = true
	res.Token.SessionID = newsess

	if err = jswr.Encode(res); err != nil {
		lblog.LogEvent("SvMgr", "SaveProfile", "error", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	lblog.LogEvent("SvMgr", "SaveProfile", "info", "complete")
}

//SavePassword saves a password change
func (sv *SvMgr) SavePassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", EnvDomain)
	w.Header().Add("Content-Type", "application/json; charset=UTF-8")

	//handle OPTIONS request
	if r.Method == "OPTIONS" {
		w.Header().Add("Access-Control-Allow-Methods", "POST")
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type,x-lidstromberg-api")
		return
	}
	// prepare the json writer for outgoing messages
	jswr := json.NewEncoder(w)

	//prepare result
	res := &BoolResult{Header: &HdlError{StatusID: http.StatusOK}, Token: &Token{}}

	//this is wrapped by middleware, authorization is in the metdata
	ctx := r.Context()

	//get the jwt
	sessid := ctx.Value(EnvCtxKey).(string)

	if sessid == "" {
		lblog.LogEvent("SvMgr", "SavePassword", "error", ErrSessionNotExist.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusForbidden
		res.Header.Error = ErrSessionNotExist.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//check that the session is valid
	_, err := sv.sm.IsSessionValid(ctx, sessid)

	if err != nil {
		lblog.LogEvent("SvMgr", "SavePassword", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusForbidden
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//set a context timeout
	ctx, cancel := context.WithTimeout(ctx, EnvCtxTimeout)
	defer cancel()

	//if the token was valid then start the refresh request
	rfchn := sv.sm.RefreshSession(ctx, sessid)
	defer sess.DrainFn(rfchn)

	ac := &auth.UserAccountPasswordChange{}
	err = json.NewDecoder(r.Body).Decode(ac)
	if err != nil {
		lblog.LogEvent("SvMgr", "SavePassword", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusUnprocessableEntity
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//get the user profile
	result, err := sv.cr.SavePassword(ctx, ac.UserAccountID, ac.Password)

	//return the error
	if err != nil {
		lblog.LogEvent("SvMgr", "SavePassword", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusInternalServerError
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//get the refreshed session
	var wg sync.WaitGroup
	wg.Add(1)
	newsess := sess.PollFn(ctx, &wg, sessid, rfchn)
	wg.Wait()

	//otherwise report successful completion
	w.WriteHeader(http.StatusOK)
	res.Result = result
	res.Token.SessionID = newsess

	if err = jswr.Encode(res); err != nil {
		lblog.LogEvent("SvMgr", "SavePassword", "error", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	lblog.LogEvent("SvMgr", "SavePassword", "info", "complete")
}

//RequestReset despatches password reset email
func (sv *SvMgr) RequestReset(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", EnvDomain)
	w.Header().Add("Content-Type", "application/json; charset=UTF-8")

	//handle OPTIONS request
	if r.Method == "OPTIONS" {
		w.Header().Add("Access-Control-Allow-Methods", "POST")
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type,x-lidstromberg-api")
		return
	}
	// prepare the json writer for outgoing messages
	jswr := json.NewEncoder(w)

	//prepare result
	res := &ConfirmTokenResult{Header: &HdlError{StatusID: http.StatusOK}}

	//this is wrapped by middleware, authorization is in the metdata
	ctx := context.Background()

	ac := &UserEmailRequest{}
	err := json.NewDecoder(r.Body).Decode(ac)
	if err != nil {
		lblog.LogEvent("SvMgr", "RequestReset", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusUnprocessableEntity
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//get the user profile
	conftoken, err := sv.cr.RequestReset(ctx, ac.Email, sv.appname)

	//return the error
	if err != nil {
		lblog.LogEvent("SvMgr", "RequestReset", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusInternalServerError
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}
	lblog.LogEvent("SvMgr", "RequestReset", "conftoken", conftoken)

	//otherwise report successful completion
	w.WriteHeader(http.StatusOK)
	res.ConfirmToken = conftoken

	if err = jswr.Encode(res); err != nil {
		lblog.LogEvent("SvMgr", "RequestReset", "error", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	lblog.LogEvent("SvMgr", "RequestReset", "info", "complete")
}

//FinishReset saves the account reset details
func (sv *SvMgr) FinishReset(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", EnvDomain)
	w.Header().Add("Content-Type", "application/json; charset=UTF-8")

	//handle OPTIONS request
	if r.Method == "OPTIONS" {
		w.Header().Add("Access-Control-Allow-Methods", "POST")
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type,x-lidstromberg-api")
		return
	}
	// prepare the json writer for outgoing messages
	jswr := json.NewEncoder(w)

	//prepare result
	res := &ConfirmationResult{Header: &HdlError{StatusID: http.StatusOK}}

	//requires new context
	ctx := context.Background()

	ac := &UserResetRequest{}
	err := json.NewDecoder(r.Body).Decode(ac)
	if err != nil {
		lblog.LogEvent("SvMgr", "FinishReset", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusUnprocessableEntity
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//finish the reset request
	confres, err := sv.cr.FinishReset(ctx, ac.ConfirmToken, ac.Password)

	//return the error
	if err != nil {
		lblog.LogEvent("SvMgr", "FinishReset", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusInternalServerError
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//otherwise report successful completion
	w.WriteHeader(http.StatusOK)
	res.RedirectLink = confres.RedirectLink

	if err = jswr.Encode(res); err != nil {
		lblog.LogEvent("SvMgr", "FinishReset", "error", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	lblog.LogEvent("SvMgr", "FinishReset", "info", "complete")
}

//ToggleTwoFA toggles two factor authentication
func (sv *SvMgr) ToggleTwoFA(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", EnvDomain)
	w.Header().Add("Content-Type", "application/json; charset=UTF-8")

	//handle OPTIONS request
	if r.Method == "OPTIONS" {
		w.Header().Add("Access-Control-Allow-Methods", "POST")
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type,x-lidstromberg-api")
		return
	}
	// prepare the json writer for outgoing messages
	jswr := json.NewEncoder(w)

	//prepare result
	res := &AccountOtpResult{Header: &HdlError{StatusID: http.StatusOK}, Token: &Token{}, Otp: &auth.ToggleOtpResult{}}

	//this is wrapped by middleware, authorization is in the metdata
	ctx := r.Context()

	//get the jwt
	sessid := ctx.Value(EnvCtxKey).(string)

	if sessid == "" {
		lblog.LogEvent("SvMgr", "ToggleTwoFA", "error", ErrSessionNotExist.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusForbidden
		res.Header.Error = ErrSessionNotExist.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//check that the session is valid
	_, err := sv.sm.IsSessionValid(ctx, sessid)

	if err != nil {
		lblog.LogEvent("SvMgr", "ToggleTwoFA", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusForbidden
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//set a context timeout
	ctx, cancel := context.WithTimeout(ctx, EnvCtxTimeout)
	defer cancel()

	//if the token was valid then start the refresh request
	rfchn := sv.sm.RefreshSession(ctx, sessid)
	defer sess.DrainFn(rfchn)

	ac := &OtpToggleRequest{}
	err = json.NewDecoder(r.Body).Decode(ac)
	if err != nil {
		lblog.LogEvent("SvMgr", "ToggleTwoFA", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusInternalServerError
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//toggle the Otp
	var otpr1 *auth.ToggleOtpResult
	if ac.Otp {
		otp1 := sv.cr.ToggleTwoFactor(ctx, EnvDomain, ac.UserAccountID, EnvPeriod, ac.Otp, true)

		otpr1 = otp1
	} else {
		otp1 := sv.cr.ToggleTwoFactor(ctx, EnvDomain, ac.UserAccountID, EnvPeriod, ac.Otp, false)

		otpr1 = otp1
	}

	//return the error
	if otpr1.Check.Error != nil {
		lblog.LogEvent("SvMgr", "ToggleTwoFA", "error", otpr1.Check.Error.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusInternalServerError
		res.Header.Error = otpr1.Check.Error.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//get the refreshed session
	var wg sync.WaitGroup
	wg.Add(1)
	newsess := sess.PollFn(ctx, &wg, sessid, rfchn)
	wg.Wait()

	//otherwise report successful completion
	w.WriteHeader(http.StatusOK)
	res.Token.SessionID = newsess
	res.Otp = otpr1

	if err = jswr.Encode(res); err != nil {
		lblog.LogEvent("SvMgr", "ToggleTwoFA", "error", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	lblog.LogEvent("SvMgr", "ToggleTwoFA", "info", "complete")
}

//LoginOtp logs in an existing account
func (sv *SvMgr) LoginOtp(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", EnvDomain)
	w.Header().Add("Content-Type", "application/json; charset=UTF-8")

	//handle OPTIONS request
	if r.Method == "OPTIONS" {
		w.Header().Add("Access-Control-Allow-Methods", "POST")
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type,x-lidstromberg-api")
		return
	}
	// prepare the json writer for outgoing messages
	jswr := json.NewEncoder(w)

	//prepare result
	res := &LoginResult{Header: &HdlError{StatusID: http.StatusOK}, Token: &Token{}}

	//requires new context
	ctx := r.Context()

	ac := &auth.OtpCandidate{}
	err := json.NewDecoder(r.Body).Decode(ac)
	if err != nil {
		lblog.LogEvent("SvMgr", "LoginOtp", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusUnprocessableEntity
		res.Header.Error = err.Error()

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//verify the otp
	otpres := sv.cr.VerifyOtp(ctx, ac)
	if otpres.Check.Error != nil {
		lblog.LogEvent("SvMgr", "LoginOtp", "error", otpres.Check.Error.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusInternalServerError
		res.Header.Error = otpres.Check.Error.Error()
		res.LoginID = ac.LoginID

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//activate the login candidate
	shdr, err := sv.cr.ActivateLoginCandidate(ctx, ac.LoginID)
	if err != nil {
		lblog.LogEvent("SvMgr", "LoginOtp-ActivateLC", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusInternalServerError
		res.Header.Error = err.Error()
		res.LoginID = ac.LoginID

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//get the jwt
	sessid, err := sv.sm.NewSession(ctx, shdr)
	if err != nil {
		lblog.LogEvent("SvMgr", "Login-NewSession", "error", err.Error())

		w.WriteHeader(http.StatusOK)
		res.Header.StatusID = http.StatusInternalServerError
		res.Header.Error = err.Error()
		res.LoginID = ac.LoginID

		if errJ := jswr.Encode(res); errJ != nil {
			http.Error(w, errJ.Error(), http.StatusInternalServerError)
		}
		return
	}

	//otherwise report successful completion
	w.WriteHeader(http.StatusOK)
	res.Token.SessionID = sessid

	if err = jswr.Encode(res); err != nil {
		lblog.LogEvent("SvMgr", "Login", "error", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	lblog.LogEvent("SvMgr", "Login", "info", "complete")
}

//Hb is a simple echo heartbeat test
func (sv *SvMgr) Hb(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	lblog.LogEvent("SvMgr", "Hb", "info", "ok")
}

//RequestCheck reports request sequence
func (sv *SvMgr) RequestCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	// prepare the json writer for outgoing messages
	jswr := json.NewEncoder(w)

	rqs := strings.Split(r.Header.Get("X-Forwarded-For"), ",")

	for _, item := range rqs {
		if err := jswr.Encode(item); err != nil {
			lblog.LogEvent("SvMgr", "RequestCheck", "error", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	lblog.LogEvent("SvMgr", "RequestCheck", "info", "ok")
}

//RootWarning is service root which is not in use
func (sv *SvMgr) RootWarning(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusForbidden)
}

//NewSvMgr returns an auth service
func NewSvMgr(ctx context.Context, appName string) (*SvMgr, error) {
	//create a config map
	bc := lbcf.NewConfig(ctx)

	//preflight
	preflight()

	//create a keypair
	kpr, err := kp.NewKeyPair(ctx, bc)

	if err != nil {
		return nil, err
	}

	//create a mail client
	mc := sendgrid.NewSendClient(bc.GetConfigValue(ctx, "EnvSendMailKey"))

	//auth.NewCoreCredentialMgr loads the config
	cr, err := auth.NewCoreCredentialMgr(ctx, bc, kpr, mc)

	if err != nil {
		return nil, err
	}

	//create a new session manager
	sm, err := sess.NewSessMgr(ctx, bc, kpr)

	if err != nil {
		return nil, err
	}

	//gateway manager
	gt, err := gt.NewGtwyMgr(ctx, bc)

	if err != nil {
		return nil, err
	}

	//create the service manager
	rn := &SvMgr{bc: bc, sm: sm, cr: cr, gt: gt, appname: appName}

	//create a mux
	mx := mux.NewRouter()

	//redirect route to service base
	mx.HandleFunc("/", rn.RootWarning).Headers("X-Robots-Tag", "no-index,no-follow")

	//create the healthcheck route
	mx.HandleFunc("/_ah/health", rn.Hb)
	//create the healthcheck route
	mx.HandleFunc("/_ah/rq", rn.RequestCheck)

	//create the profile route and wrap it with the authorisation middleware
	au := mux.NewRouter()
	mx.PathPrefix("/auth/api").Handler(negroni.New(
		negroni.HandlerFunc(rn.IsApproved),
		negroni.Wrap(au)))

	//create the base app subrouter
	bsesub1 := au.PathPrefix("/auth/api").Subrouter()
	//create the v1 subrouter from the base
	v1 := bsesub1.PathPrefix("/v1").Subrouter()

	//create the profile route and wrap it with the authorisation middleware
	sc := mux.NewRouter()
	v1.PathPrefix("/profile").Handler(negroni.New(
		negroni.HandlerFunc(rn.HasAuthorisation),
		negroni.Wrap(sc)))

	//create the profile routes
	prf := sc.PathPrefix("/auth/api/v1/profile").Subrouter()
	prf.HandleFunc("/store", rn.SaveProfile).Methods("OPTIONS", "POST")
	prf.HandleFunc("/credential", rn.SavePassword).Methods("OPTIONS", "POST")
	prf.HandleFunc("/tfa", rn.ToggleTwoFA).Methods("OPTIONS", "POST")
	prf.HandleFunc("/detail", rn.GetLoginProfile).Methods("OPTIONS", "POST")

	//create the global subrouter from v1
	glb := v1.PathPrefix("/global").Subrouter()
	//create the global routes
	glb.HandleFunc("/register", rn.Register).Methods("OPTIONS", "POST")
	glb.HandleFunc("/otp", rn.LoginOtp).Methods("OPTIONS", "POST")
	glb.HandleFunc("/login", rn.Login).Methods("OPTIONS", "POST")
	glb.HandleFunc("/confirmer/{token}", rn.ConfirmReg).Methods("GET")
	//create the reset subrouter from global
	rst := glb.PathPrefix("/reset").Subrouter()
	//create the reset routes
	rst.HandleFunc("/start", rn.RequestReset).Methods("OPTIONS", "POST")
	rst.HandleFunc("/finish", rn.FinishReset).Methods("OPTIONS", "POST")

	rn.Mx = mx

	//return the service manager
	return rn, nil
}
