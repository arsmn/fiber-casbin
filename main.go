package fibercasbin

import (
	"log"
	"strings"

	"github.com/casbin/casbin"
	"github.com/casbin/casbin/persist"
	"github.com/gofiber/fiber"
)

type Config struct {
	ModelFilePath string
	PolicyAdapter persist.Adapter
	SubLookupFn   SubjectLookupFunc
	Unauthorized  func(*fiber.Ctx)
	Forbidden     func(*fiber.Ctx)
}

type CasbinMiddleware struct {
	config      Config
	enforcer    *casbin.Enforcer
	subLookupFn SubjectLookupFunc
}

type SubjectLookupFunc func(*fiber.Ctx) string

func New(config ...Config) *CasbinMiddleware {

	var cfg Config
	if len(config) > 0 {
		cfg = config[0]
	}

	if cfg.SubLookupFn == nil {
		log.Fatal("Fiber: Casbin middleware requires SubjectLookup function")
	}

	if cfg.ModelFilePath == "" {
		log.Fatal("Fiber: Casbin middleware requires model file path")
	}

	if cfg.PolicyAdapter == nil {
		log.Fatal("Fiber: Casbin middleware requires a policy adapter")
	}

	if cfg.Unauthorized == nil {
		cfg.Unauthorized = func(c *fiber.Ctx) {
			c.SendStatus(fiber.StatusUnauthorized)
		}
	}

	if cfg.Forbidden == nil {
		cfg.Forbidden = func(c *fiber.Ctx) {
			c.SendStatus(fiber.StatusForbidden)
		}
	}

	return &CasbinMiddleware{
		config:      cfg,
		subLookupFn: cfg.SubLookupFn,
		enforcer:    casbin.NewEnforcer(cfg.ModelFilePath, cfg.PolicyAdapter),
	}
}

type validationRule int

const (
	matchAll validationRule = iota
	atLeastOne
)

var MatchAll = func(o *Options) {
	o.ValidationRule = matchAll
}

var AtLeastOne = func(o *Options) {
	o.ValidationRule = atLeastOne
}

type PermissionParserFunc func(str string) (string, string)

func permissionParserWithSeperator(sep string) PermissionParserFunc {
	return func(str string) (string, string) {
		if !strings.Contains(str, sep) {
			return "", ""
		}
		vals := strings.Split(str, sep)
		return vals[0], vals[1]
	}
}

func PermissionParserWithSeperator(sep string) func(o *Options) {
	return func(o *Options) {
		o.PermissionParser = permissionParserWithSeperator(sep)
	}
}

type Options struct {
	ValidationRule   validationRule
	PermissionParser PermissionParserFunc
}

func (cm *CasbinMiddleware) RequiresPermissions(permissions []string, opts ...func(o *Options)) func(*fiber.Ctx) {

	options := &Options{
		ValidationRule:   matchAll,
		PermissionParser: permissionParserWithSeperator(":"),
	}

	for _, o := range opts {
		o(options)
	}

	for _, permission := range permissions {
		obj, act := options.PermissionParser(permission)
		if obj == "" || act == "" {
			log.Fatalf("Fiber: Casbin middleware could not parse permission -> %s", permission)
		}
	}

	return func(c *fiber.Ctx) {
		if len(permissions) == 0 {
			c.Next()
			return
		}

		sub := cm.subLookupFn(c)
		if len(sub) == 0 {
			cm.config.Unauthorized(c)
			return
		}

		if options.ValidationRule == matchAll {
			for _, permission := range permissions {
				obj, act := options.PermissionParser(permission)
				if ok := cm.enforcer.Enforce(sub, obj, act); !ok {
					cm.config.Forbidden(c)
					return
				}
			}
			c.Next()
			return
		} else if options.ValidationRule == atLeastOne {
			for _, permission := range permissions {
				obj, act := options.PermissionParser(permission)
				if ok := cm.enforcer.Enforce(sub, obj, act); ok {
					c.Next()
					return
				}
			}
			cm.config.Forbidden(c)
			return
		}

	}
}

func (cm *CasbinMiddleware) RoutePermission() func(*fiber.Ctx) {
	return func(c *fiber.Ctx) {

		sub := cm.subLookupFn(c)
		if len(sub) == 0 {
			cm.config.Unauthorized(c)
			return
		}

		if ok := cm.enforcer.Enforce(sub, c.Path(), c.Method()); !ok {
			cm.config.Forbidden(c)
			return
		}

		c.Next()
		return
	}
}
