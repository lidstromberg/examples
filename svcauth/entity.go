package main

import (
	auth "github.com/lidstromberg/auth"
)

//HdlError is a handler error wrapper
type HdlError struct {
	StatusID int    `json:"statusid"`
	Error    string `json:"error"`
}

//Token is the jwt container
type Token struct {
	SessionID string `json:"sessionid"`
}

//TokenResult wraps Token
type TokenResult struct {
	Header *HdlError `json:"header"`
	Token  *Token    `json:"token"`
}

//BoolResult generic bool result
type BoolResult struct {
	Header *HdlError `json:"header"`
	Token  *Token    `json:"token"`
	Result bool      `json:"result"`
}

//LoginResult wraps login and handler error
type LoginResult struct {
	Header  *HdlError `json:"header"`
	Token   *Token    `json:"token"`
	LoginID string    `json:"loginid"`
}

//ConfirmationResult wraps account confirmation result and handler error
type ConfirmationResult struct {
	Header       *HdlError `json:"header"`
	RedirectLink string    `json:"redirectlink"`
}

//LoginProfileResult wraps account and token
type LoginProfileResult struct {
	Header  *HdlError         `json:"header"`
	Token   *Token            `json:"token"`
	Account *auth.UserAccount `json:"account"`
}

//ConfirmTokenResult wraps a confirmation token
type ConfirmTokenResult struct {
	Header       *HdlError `json:"header"`
	ConfirmToken string    `json:"confirmtoken"`
}

//RegisterResult wraps a token and confirmation token
type RegisterResult struct {
	Header        *HdlError `json:"header"`
	UserAccountID string    `json:"useraccountid"`
	ConfirmToken  string    `json:"confirmtoken"`
}

//AccountOtpResult wraps otpcheck and token
type AccountOtpResult struct {
	Header *HdlError             `json:"header"`
	Token  *Token                `json:"token"`
	Otp    *auth.ToggleOtpResult `json:"otp"`
}

//UpdateableUserAccount represents the updateable element of the useraccount
type UpdateableUserAccount struct {
	UserAccountID string `json:"useraccountid"`
	Email         string `json:"email"`
	PhoneNumber   string `json:"phonenumber"`
}

//UserAccountRequest represents a minimal identifier for an authenticated user account
type UserAccountRequest struct {
	UserAccountID string `json:"useraccountid"`
}

//UserEmailRequest represents a minimal identifier for an unauthenticated user account
type UserEmailRequest struct {
	Email string `json:"email"`
}

//UserResetRequest represents a reset finalisation request
type UserResetRequest struct {
	ConfirmToken string `json:"confirmtoken"`
	Password     string `json:"password"`
}

//OtpToggleRequest toggle 2FA request
type OtpToggleRequest struct {
	UserAccountID string `json:"useraccountid"`
	Otp           bool   `json:"otp"`
}
