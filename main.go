package fibercasbin

import (
	"github.com/gofiber/fiber/v2"
)

// CasbinMiddleware ...
type CasbinMiddleware struct {
	config Config
}

// New creates an authorization middleware for use in Fiber
func New(config ...Config) *CasbinMiddleware {
	return &CasbinMiddleware{
		config: configDefault(config...),
	}
}

// RequiresPermissions tries to find the current subject and determine if the
// subject has the required permissions according to predefined Casbin policies.
func (cm *CasbinMiddleware) RequiresPermissions(permissions []string, opts ...Option) fiber.Handler {
	options := optionsDefault(opts...)

	return func(c *fiber.Ctx) error {
		if len(permissions) == 0 {
			return c.Next()
		}

		sub := cm.config.Lookup(c)
		if len(sub) == 0 {
			return cm.config.Unauthorized(c)
		}

		if options.ValidationRule == MatchAllRule {
			for _, permission := range permissions {
				vals := append([]string{sub}, options.PermissionParser(permission)...)
				if ok, err := cm.config.Enforcer.Enforce(stringSliceToInterfaceSlice(vals)...); err != nil {
					return c.SendStatus(fiber.StatusInternalServerError)
				} else if !ok {
					return cm.config.Forbidden(c)
				}
			}
			return c.Next()
		} else if options.ValidationRule == AtLeastOneRule {
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
func (cm *CasbinMiddleware) RequiresRoles(roles []string, opts ...Option) fiber.Handler {
	options := optionsDefault(opts...)

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

		if options.ValidationRule == MatchAllRule {
			for _, role := range roles {
				if !containsString(userRoles, role) {
					return cm.config.Forbidden(c)
				}
			}
			return c.Next()
		} else if options.ValidationRule == AtLeastOneRule {
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
