package fibercasbin

import (
	"log"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/persist"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/gofiber/fiber/v2"
)

// Config holds the configuration for the middleware
type Config struct {
	// ModelFilePath is path to model file for Casbin.
	// Optional. Default: "./model.conf".
	ModelFilePath string

	// PolicyAdapter is an interface for different persistent providers.
	// Optional. Default: fileadapter.NewAdapter("./policy.csv").
	PolicyAdapter persist.Adapter

	// Enforcer is an enforcer. If you want to use your own enforcer.
	// Optional. Default: nil
	Enforcer *casbin.Enforcer

	// Lookup is a function that is used to look up current subject.
	// An empty string is considered as unauthenticated user.
	// Optional. Default: func(c *fiber.Ctx) string { return "" }
	Lookup func(*fiber.Ctx) string

	// Unauthorized defines the response body for unauthorized responses.
	// Optional. Default: func(c *fiber.Ctx) error { return c.SendStatus(401) }
	Unauthorized fiber.Handler

	// Forbidden defines the response body for forbidden responses.
	// Optional. Default: func(c *fiber.Ctx) error { return c.SendStatus(403) }
	Forbidden fiber.Handler
}

// CasbinMiddleware ...
type CasbinMiddleware struct {
	config Config
}

// New creates an authorization middleware for use in Fiber
func New(config ...Config) *CasbinMiddleware {
	var cfg Config
	if len(config) > 0 {
		cfg = config[0]
	}

	if cfg.Enforcer == nil {
		if cfg.ModelFilePath == "" {
			cfg.ModelFilePath = "./model.conf"
		}

		if cfg.PolicyAdapter == nil {
			cfg.PolicyAdapter = fileadapter.NewAdapter("./policy.csv")
		}

		enforcer, err := casbin.NewEnforcer(cfg.ModelFilePath, cfg.PolicyAdapter)
		if err != nil {
			log.Fatalf("Fiber: Casbin middleware error -> %v", err)
		}

		cfg.Enforcer = enforcer
	}

	if cfg.Lookup == nil {
		cfg.Lookup = func(c *fiber.Ctx) string { return "" }
	}

	if cfg.Unauthorized == nil {
		cfg.Unauthorized = func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusUnauthorized)
		}
	}

	if cfg.Forbidden == nil {
		cfg.Forbidden = func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusForbidden)
		}
	}

	return &CasbinMiddleware{
		config: cfg,
	}
}

type validationRule int

const (
	matchAll validationRule = iota
	atLeastOne
)

// MatchAll is an option that defines all permissions
// or roles should match the user.
var MatchAll = func(o *Options) {
	o.ValidationRule = matchAll
}

// AtLeastOne is an option that defines at least on of
// permissions or roles should match to pass.
var AtLeastOne = func(o *Options) {
	o.ValidationRule = atLeastOne
}

// PermissionParserFunc is used for parsing the permission
// to extract object and action usually
type PermissionParserFunc func(str string) []string

func permissionParserWithSeperator(sep string) PermissionParserFunc {
	return func(str string) []string {
		return strings.Split(str, sep)
	}
}

// PermissionParserWithSeperator is an option that parses permission
// with seperators
func PermissionParserWithSeperator(sep string) func(o *Options) {
	return func(o *Options) {
		o.PermissionParser = permissionParserWithSeperator(sep)
	}
}

// Options holds options of middleware
type Options struct {
	ValidationRule   validationRule
	PermissionParser PermissionParserFunc
}

// RequiresPermissions tries to find the current subject and determine if the
// subject has the required permissions according to predefined Casbin policies.
func (cm *CasbinMiddleware) RequiresPermissions(permissions []string, opts ...func(o *Options)) fiber.Handler {

	options := &Options{
		ValidationRule:   matchAll,
		PermissionParser: permissionParserWithSeperator(":"),
	}

	for _, o := range opts {
		o(options)
	}

	return func(c *fiber.Ctx) error {
		if len(permissions) == 0 {
			return c.Next()
		}

		sub := cm.config.Lookup(c)
		if len(sub) == 0 {
			return cm.config.Unauthorized(c)
		}

		if options.ValidationRule == matchAll {
			for _, permission := range permissions {
				vals := append([]string{sub}, options.PermissionParser(permission)...)
				if ok, err := cm.config.Enforcer.Enforce(stringSliceToInterfaceSlice(vals)...); err != nil {
					return c.SendStatus(fiber.StatusInternalServerError)
				} else if !ok {
					return cm.config.Forbidden(c)
				}
			}
			return c.Next()
		} else if options.ValidationRule == atLeastOne {
			for _, permission := range permissions {
				vals := append([]string{sub}, options.PermissionParser(permission)...)
				if ok, err := cm.config.Enforcer.Enforce(stringSliceToInterfaceSlice(vals)...); err != nil {
					return c.SendStatus(fiber.StatusInternalServerError)
				} else if ok {
					return c.Next()
				}
			}
			return cm.config.Forbidden(c)
		}

		return c.Next()
	}
}

// RoutePermission tries to find the current subject and determine if the
// subject has the required permissions according to predefined Casbin policies.
// This method uses http Path and Method as object and action.
func (cm *CasbinMiddleware) RoutePermission() fiber.Handler {
	return func(c *fiber.Ctx) error {
		sub := cm.config.Lookup(c)
		if len(sub) == 0 {
			return cm.config.Unauthorized(c)
		}

		if ok, err := cm.config.Enforcer.Enforce(sub, c.Path(), c.Method()); err != nil {
			return c.SendStatus(fiber.StatusInternalServerError)
		} else if !ok {
			return cm.config.Forbidden(c)
		}

		return c.Next()
	}
}

// RequiresRoles tries to find the current subject and determine if the
// subject has the required roles according to predefined Casbin policies.
func (cm *CasbinMiddleware) RequiresRoles(roles []string, opts ...func(o *Options)) fiber.Handler {
	options := &Options{
		ValidationRule:   matchAll,
		PermissionParser: permissionParserWithSeperator(":"),
	}

	for _, o := range opts {
		o(options)
	}

	return func(c *fiber.Ctx) error {
		if len(roles) == 0 {
			return c.Next()
		}

		sub := cm.config.Lookup(c)
		if len(sub) == 0 {
			return cm.config.Unauthorized(c)
		}

		userRoles, err := cm.config.Enforcer.GetRolesForUser(sub)
		if err != nil {
			return c.SendStatus(fiber.StatusInternalServerError)
		}

		if options.ValidationRule == matchAll {
			for _, role := range roles {
				if !containsString(userRoles, role) {
					return cm.config.Forbidden(c)
				}
			}
			return c.Next()
		} else if options.ValidationRule == atLeastOne {
			for _, role := range roles {
				if containsString(userRoles, role) {
					return c.Next()
				}
			}
			return cm.config.Forbidden(c)
		}

		return c.Next()
	}
}
