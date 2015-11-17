// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package v4 // import "gopkg.in/juju/charmstore.v5-unstable/internal/v4"

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gopkg.in/errgo.v1"
	"gopkg.in/juju/charmrepo.v1/csclient/params"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
	"gopkg.in/macaroon.v1"

	"gopkg.in/juju/charmstore.v5-unstable/internal/router"
)

const (
	basicRealm                  = "CharmStore4"
	promulgatorsGroup           = "promulgators"
	opReadArchive     operation = "read-archive"
	opNoOp            operation = "no-op"
)

type operation string

type checkRequest func(req *http.Request, acl []string, alwaysAuth bool, entityId *router.ResolvedURL) (authorization, []checkers.Caveat, error)

// authorize checks that the current user is authorized based on the provided
// ACL and optional entity. If an authenticated user is required, authorize tries to retrieve the
// current user in the following ways:
// - by checking that the request's headers HTTP basic auth credentials match
//   the superuser credentials stored in the API handler;
// - by checking that there is a valid macaroon in the request's cookies.
// A params.ErrUnauthorized error is returned if superuser credentials fail;
// otherwise a macaroon is minted and a httpbakery discharge-required
// error is returned holding the macaroon.
//
// This method also sets h.auth to the returned authorization info.
func (h *ReqHandler) authorize(req *http.Request, acl []string, alwaysAuth bool, entityId *router.ResolvedURL, op operation) (authorization, error) {
	logger.Infof(
		"authorize, auth location %q, terms location %q, acl %q, path: %q, method: %q, op %v",
		h.handler.config.IdentityLocation,
		h.handler.config.TermsLocation,
		acl,
		req.URL.Path,
		req.Method,
		op)

	checkerFnc, ok := h.requestCheckers[op]
	if !ok {
		return authorization{}, errgo.New("unknown operation")
	}
	auth, caveats, verr := checkerFnc(req, acl, alwaysAuth, entityId)
	if verr == nil {
		h.auth = auth
		logger.Errorf("XXX NO ERR RETURNED %#v", auth)
		return auth, nil
	}
	logger.Errorf("XXX CHECKER FNC RETURNED %v %#v", verr, caveats)
	if _, ok := errgo.Cause(verr).(*bakery.VerificationError); !ok {
		return authorization{}, errgo.Mask(verr, errgo.Is(params.ErrUnauthorized))
	}
	logger.Errorf("XXX AUTHORIZE RETURNING A NEW MAC DISCHARGE ERR")
	// Macaroon verification failed: mint a new macaroon.
	m, err := h.newMacaroon(caveats...)
	if err != nil {
		return authorization{}, errgo.Notef(err, "cannot mint macaroon")
	}
	// Request that this macaroon be supplied for all requests
	// to the whole handler.
	// TODO use a relative URL here: router.RelativeURLPath(req.RequestURI, "/")
	cookiePath := "/"
	return authorization{}, httpbakery.NewDischargeRequiredErrorForRequest(m, cookiePath, verr, req)
}

// checkRequest checks for any authorization tokens in the request and returns any
// found as an authorization. If no suitable credentials are found, or an error occurs,
// then a zero valued authorization is returned.
// It also checks any first party caveats. If the entityId is provided, it will
// be used to check any "is-entity" first party caveat.
func (h *ReqHandler) checkRequest(req *http.Request, acl []string, alwaysAuth bool, entityId *router.ResolvedURL) (authorization, []checkers.Caveat, error) {
	logger.Errorf("XXX CHECK REQUEST \n\n\n")
	if !alwaysAuth {
		// No need to authenticate if the ACL is open to everyone.
		for _, name := range acl {
			if name == params.Everyone {
				return authorization{}, nil, nil
			}
		}
	}

	user, passwd, err := parseCredentials(req)
	if err == nil {
		if user != h.handler.config.AuthUsername || passwd != h.handler.config.AuthPassword {
			return authorization{}, nil, errgo.WithCausef(nil, params.ErrUnauthorized, "invalid user name or password")
		}
		return authorization{Admin: true}, nil, nil
	}
	bk := h.Store.Bakery
	if errgo.Cause(err) != errNoCreds ||
		bk == nil ||
		h.handler.config.IdentityLocation == "" {
		return authorization{}, nil, errgo.WithCausef(err, params.ErrUnauthorized, "authentication failed")
	}
	if errgo.Cause(err) != errNoCreds ||
		bk == nil ||
		h.handler.config.IdentityLocation == "" {
		return authorization{}, nil, errgo.WithCausef(err, params.ErrUnauthorized, "authentication failed")
	}

	attrMap, err := httpbakery.CheckRequest(bk, req, nil, checkers.New(
		checkers.CheckerFunc{
			Condition_: "is-entity",
			Check_: func(_, arg string) error {
				if entityId == nil {
					return errgo.Newf("API operation does not involve expected entity %v", arg)
				}
				purl := entityId.PromulgatedURL()
				if entityId.URL.String() == arg || purl != nil && purl.String() == arg {
					// We allow either the non-promulgated or the promulgated
					// URL form.
					return nil
				}
				return errgo.Newf("API operation on entity %v, want %v", entityId, arg)
			},
		},
		checkers.OperationChecker(opNoOp),
	))
	if err != nil {
		return authorization{}, []checkers.Caveat{checkers.DenyCaveat(string(opReadArchive))}, errgo.Mask(err, errgo.Any)
	}
	auth := authorization{
		Admin:    false,
		Username: attrMap[usernameAttr],
	}
	if err := h.checkACLMembership(auth, acl); err != nil {
		return authorization{}, nil, errgo.WithCausef(err, params.ErrUnauthorized, "")
	}
	return auth, nil, nil
}

// checkRequest checks for any authorization tokens in the request and returns any
// found as an authorization. If no suitable credentials are found, or an error occurs,
// then a zero valued authorization is returned.
// It also checks any first party caveats. If the entityId is provided, it will
// be used to check any "is-entity" first party caveat.
func (h *ReqHandler) checkReadArchiveRequest(req *http.Request, acl []string, alwaysAuth bool, entityId *router.ResolvedURL) (authorization, []checkers.Caveat, error) {
	logger.Errorf("XXX CHECK READ ARCHIVE REQUEST\n\n\n")
	entity, err := h.Store.FindEntity(entityId)
	if err != nil {
		logger.Errorf("XXX ENTITY NOT FOUND")
		return authorization{}, nil, errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	baseEntity, err := h.Store.FindBaseEntity(&entityId.URL, "acls")
	if err != nil {
		return authorization{}, nil, errgo.Mask(err)
	}
	if len(entity.CharmMeta.Terms) == 0 {
		// No need to authenticate if the ACL is open to everyone.
		for _, name := range baseEntity.ACLs.Read {
			if name == params.Everyone {
				return authorization{}, nil, nil
			}
		}
	}
	user, passwd, err := parseCredentials(req)
	if err == nil {
		if user != h.handler.config.AuthUsername || passwd != h.handler.config.AuthPassword {
			logger.Errorf("XXX WRONG USERNAME/PASSWORD")
			return authorization{}, nil, errgo.WithCausef(nil, params.ErrUnauthorized, "invalid user name or password")
		}
		logger.Errorf("XXX FOUND CREDENTIALS")
		return authorization{Admin: true}, nil, nil
	}
	bk := h.Store.Bakery
	if errgo.Cause(err) != errNoCreds ||
		bk == nil ||
		h.handler.config.IdentityLocation == "" ||
		h.handler.config.TermsLocation == "" {
		logger.Errorf("XXX NOT CONFIGURED")
		return authorization{}, nil, errgo.WithCausef(err, params.ErrUnauthorized, "authentication failed")
	}

	attrMap, err := httpbakery.CheckRequest(bk, req, nil, checkers.New(
		checkers.CheckerFunc{
			Condition_: "is-entity",
			Check_: func(_, arg string) error {
				if entityId == nil {
					return errgo.Newf("API operation does not involve expected entity %v", arg)
				}
				purl := entityId.PromulgatedURL()
				if entityId.URL.String() == arg || purl != nil && purl.String() == arg {
					// We allow either the non-promulgated or the promulgated
					// URL form.
					return nil
				}
				logger.Errorf("XXXX API ENTITY MISMATCH %v %v", entityId, arg)
				return errgo.Newf("API operation on entity %v, want %v", entityId, arg)
			},
		},
		checkers.OperationChecker(string(opReadArchive)),
	))
	if err != nil {
		logger.Errorf("XXX VERIFICATION FAILED - CREATING CAVEATS")
		caveats := []checkers.Caveat{
			checkers.AllowCaveat(string(opReadArchive)),
			checkers.Caveat{Condition: fmt.Sprintf("is-entity %s", entityId.String())},
		}
		if len(entity.CharmMeta.Terms) > 0 {
			caveats = append(
				caveats,
				checkers.Caveat{h.handler.config.TermsLocation, fmt.Sprintf("has-agreed %s", strings.Join(entity.CharmMeta.Terms, ","))},
			)
		}
		return authorization{}, caveats, errgo.Mask(err, errgo.Any)
	}
	auth := authorization{
		Admin:    false,
		Username: attrMap[usernameAttr],
	}
	logger.Errorf("XXX ACL %#v", baseEntity.ACLs.Read)
	if err := h.checkACLMembership(auth, baseEntity.ACLs.Read); err != nil {
		return authorization{}, nil, errgo.WithCausef(err, params.ErrUnauthorized, "")
	}
	h.auth = auth
	return auth, nil, nil
}

// AuthorizeEntity checks that the given HTTP request
// can access the entity with the given id.
func (h *ReqHandler) AuthorizeEntity(id *router.ResolvedURL, req *http.Request) error {
	baseEntity, err := h.Store.FindBaseEntity(&id.URL, "acls")
	if err != nil {
		if errgo.Cause(err) == params.ErrNotFound {
			return errgo.WithCausef(nil, params.ErrNotFound, "entity %q not found", id)
		}
		return errgo.Notef(err, "cannot retrieve entity %q for authorization", id)
	}
	return h.authorizeWithPerms(req, baseEntity.ACLs.Read, baseEntity.ACLs.Write, id)
}

func (h *ReqHandler) authorizeWithPerms(req *http.Request, read, write []string, entityId *router.ResolvedURL) error {
	var acl []string
	switch req.Method {
	case "DELETE", "PATCH", "POST", "PUT":
		acl = write
	default:
		acl = read
	}
	_, err := h.authorize(req, acl, false, entityId, opNoOp)
	return err
}

const usernameAttr = "username"

// authorization conatains authorization information extracted from an HTTP request.
// The zero value for a authorization contains no privileges.
type authorization struct {
	Admin    bool
	Username string
}

func (h *ReqHandler) groupsForUser(username string) ([]string, error) {
	if h.handler.config.IdentityAPIURL == "" {
		logger.Debugf("IdentityAPIURL not configured, not retrieving groups for %s", username)
		return nil, nil
	}
	// TODO cache groups for a user
	return h.handler.identityClient.GroupsForUser(username)
}

func (h *ReqHandler) checkACLMembership(auth authorization, acl []string) error {
	if auth.Admin {
		return nil
	}
	if auth.Username == "" {
		return errgo.New("no username declared")
	}
	// First check if access is granted without querying for groups.
	for _, name := range acl {
		if name == auth.Username || name == params.Everyone {
			return nil
		}
	}
	groups, err := h.groupsForUser(auth.Username)
	if err != nil {
		logger.Errorf("cannot get groups for %q: %v", auth.Username, err)
		return errgo.Newf("access denied for user %q", auth.Username)
	}
	for _, name := range acl {
		for _, g := range groups {
			if g == name {
				return nil
			}
		}
	}
	return errgo.Newf("access denied for user %q", auth.Username)
}

const (
	defaultMacaroonExpiry = 24 * time.Hour
)

func (h *ReqHandler) newMacaroon(extraCaveats ...checkers.Caveat) (*macaroon.Macaroon, error) {
	caveats := []checkers.Caveat{
		checkers.NeedDeclaredCaveat(checkers.Caveat{
			Location:  h.handler.config.IdentityLocation,
			Condition: "is-authenticated-user",
		}, usernameAttr),
		checkers.TimeBeforeCaveat(time.Now().Add(defaultMacaroonExpiry)),
	}
	caveats = append(caveats, extraCaveats...)
	// TODO generate different caveats depending on the requested operation
	// and whether there's a charm id or not.
	// Mint an appropriate macaroon and send it back to the client.
	return h.Store.Bakery.NewMacaroon("", nil, caveats)
}

var errNoCreds = errgo.New("missing HTTP auth header")

// parseCredentials parses the given request and returns the HTTP basic auth
// credentials included in its header.
func parseCredentials(req *http.Request) (username, password string, err error) {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		return "", "", errNoCreds
	}
	parts := strings.Fields(auth)
	if len(parts) != 2 || parts[0] != "Basic" {
		return "", "", errgo.New("invalid HTTP auth header")
	}
	// Challenge is a base64-encoded "tag:pass" string.
	// See RFC 2617, Section 2.
	challenge, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", errgo.New("invalid HTTP auth encoding")
	}
	tokens := strings.SplitN(string(challenge), ":", 2)
	if len(tokens) != 2 {
		return "", "", errgo.New("invalid HTTP auth contents")
	}
	return tokens[0], tokens[1], nil
}
