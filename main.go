package fiber_casbin

import (
	"log"
	"strings"

	"github.com/casbin/casbin"
	"github.com/casbin/casbin/persist"
	"github.com/gofiber/fiber"
)

type CasbinMiddleware struct {
	enforcer    *casbin.Enforcer
	subLookupFn SubjectLookup
}

type SubjectLookup func(c *fiber.Ctx) string

func New(modelPath string, adapter persist.Adapter, subLookupFn SubjectLookup) *CasbinMiddleware {
	if subLookupFn == nil {
		log.Fatal("Fiber: Casbin middleware requires SubjectLookup function")
	}

	return &CasbinMiddleware{
		enforcer:    casbin.NewEnforcer(modelPath, adapter),
		subLookupFn: subLookupFn,
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
			c.SendStatus(fiber.StatusUnauthorized)
			return
		}

		if options.ValidationRule == matchAll {
			for _, permission := range permissions {
				obj, act := options.PermissionParser(permission)
				if ok := cm.enforcer.Enforce(sub, obj, act); !ok {
					c.SendStatus(fiber.StatusForbidden)
					return
				}
			}
		} else {
			for _, permission := range permissions {
				obj, act := options.PermissionParser(permission)
				if ok := cm.enforcer.Enforce(sub, obj, act); ok {
					c.Next()
					return
				}
			}
			c.SendStatus(fiber.StatusForbidden)
			return
		}

	}
}
