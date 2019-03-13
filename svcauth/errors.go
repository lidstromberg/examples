package main

import "errors"

//errors
var (
	//ErrConfTokenNotCreated occurs if the email confirmation cycle cannot be run
	ErrConfTokenNotCreated = errors.New("could not generate a confirmation token")
	//ErrSessionNotExist occurs if the authorization header doesn't exist
	ErrSessionNotExist = errors.New("authorization header content is not present")
	//ErrConfTokenEmpty occurs when the StartAccountConfirmation does not return a confirmation token
	ErrConfTokenEmpty = errors.New("confirmation token is empty")
	//ErrSessEmpty occurs when the sessid is empty string
	ErrSessEmpty = errors.New("session id is empty")
	//ErrRqTokenEmpty occurs when the request does not supply a token on the URL
	ErrRqTokenEmpty = errors.New("could not obtain token from request query")
	//ErrUnknownReq occurs when we cannot identify the requester IP
	ErrUnknownReq = errors.New("requester IP could not be identified")
	//ErrForbiddenReq occurs when the requester IP is not approved
	ErrForbiddenReq = errors.New("requester is not authorised")
)
