package fibercasbin

import (
	"net/http"
	"testing"

	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/gofiber/fiber"
)

var (
	subjectAlice = func(c *fiber.Ctx) string { return "alice" }
	subjectBob   = func(c *fiber.Ctx) string { return "bob" }
	subjectNil   = func(c *fiber.Ctx) string { return "" }
)

func Test_RequiresPermission(t *testing.T) {

	tests := []struct {
		name        string
		lookup      func(*fiber.Ctx) string
		permissions []string
		rule        func(o *Options)
		statusCode  int
	}{
		{
			name:        "alice have permission to create blog",
			lookup:      subjectAlice,
			permissions: []string{"blog:create"},
			rule:        MatchAll,
			statusCode:  200,
		},
		{
			name:        "alice have permission to create blog",
			lookup:      subjectAlice,
			permissions: []string{"blog:create"},
			rule:        AtLeastOne,
			statusCode:  200,
		},
		{
			name:        "alice have permission to create and update blog",
			lookup:      subjectAlice,
			permissions: []string{"blog:create", "blog:update"},
			rule:        MatchAll,
			statusCode:  200,
		},
		{
			name:        "alice have permission to create comment or blog",
			lookup:      subjectAlice,
			permissions: []string{"comment:create", "blog:create"},
			rule:        AtLeastOne,
			statusCode:  200,
		},
		{
			name:        "bob have only permission to create comment",
			lookup:      subjectBob,
			permissions: []string{"comment:create", "blog:create"},
			rule:        AtLeastOne,
			statusCode:  200,
		},
		{
			name:        "unauthenticated user have no permissions",
			lookup:      subjectNil,
			permissions: []string{"comment:create"},
			rule:        MatchAll,
			statusCode:  401,
		},
		{
			name:        "bob have not permission to create blog",
			lookup:      subjectBob,
			permissions: []string{"blog:create"},
			rule:        MatchAll,
			statusCode:  403,
		},
		{
			name:        "bob have not permission to delete blog",
			lookup:      subjectBob,
			permissions: []string{"blog:delete"},
			rule:        MatchAll,
			statusCode:  403,
		},
		{
			name:        "invalid permission",
			lookup:      subjectBob,
			permissions: []string{"unknown"},
			rule:        MatchAll,
			statusCode:  500,
		},
	}

	for _, tt := range tests {
		app := *fiber.New()
		authz := New(Config{
			ModelFilePath: "./example/model.conf",
			PolicyAdapter: fileadapter.NewAdapter("./example/policy.csv"),
			Lookup:        tt.lookup,
		})

		app.Post("/blog",
			authz.RequiresPermissions(tt.permissions, tt.rule),
			func(c *fiber.Ctx) {
				c.SendStatus(200)
			},
		)

		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "/blog", nil)
			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf(`%s: %s`, t.Name(), err)
			}

			if resp.StatusCode != tt.statusCode {
				t.Fatalf(`%s: StatusCode: got %v - expected %v`, t.Name(), resp.StatusCode, tt.statusCode)
			}
		})

	}
}

func Test_RequiresRoles(t *testing.T) {

	tests := []struct {
		name       string
		lookup     func(*fiber.Ctx) string
		roles      []string
		rule       func(o *Options)
		statusCode int
	}{
		{
			name:       "alice have user role",
			lookup:     subjectAlice,
			roles:      []string{"user"},
			rule:       MatchAll,
			statusCode: 200,
		},
		{
			name:       "alice have admin role",
			lookup:     subjectAlice,
			roles:      []string{"admin"},
			rule:       AtLeastOne,
			statusCode: 200,
		},
		{
			name:       "alice have both user and admin roles",
			lookup:     subjectAlice,
			roles:      []string{"user", "admin"},
			rule:       MatchAll,
			statusCode: 200,
		},
		{
			name:       "alice have both user and admin roles",
			lookup:     subjectAlice,
			roles:      []string{"user", "admin"},
			rule:       AtLeastOne,
			statusCode: 200,
		},
		{
			name:       "bob have only user role",
			lookup:     subjectBob,
			roles:      []string{"user"},
			rule:       AtLeastOne,
			statusCode: 200,
		},
		{
			name:       "unauthenticated user have no permissions",
			lookup:     subjectNil,
			roles:      []string{"user"},
			rule:       MatchAll,
			statusCode: 401,
		},
		{
			name:       "bob have not admin role",
			lookup:     subjectBob,
			roles:      []string{"admin"},
			rule:       MatchAll,
			statusCode: 403,
		},
		{
			name:       "bob have only user role",
			lookup:     subjectBob,
			roles:      []string{"admin", "user"},
			rule:       AtLeastOne,
			statusCode: 200,
		},
		{
			name:       "invalid role",
			lookup:     subjectBob,
			roles:      []string{"unknown"},
			rule:       MatchAll,
			statusCode: 403,
		},
	}

	for _, tt := range tests {
		app := *fiber.New()
		authz := New(Config{
			ModelFilePath: "./example/model.conf",
			PolicyAdapter: fileadapter.NewAdapter("./example/policy.csv"),
			Lookup:        tt.lookup,
		})

		app.Post("/blog",
			authz.RequiresRoles(tt.roles, tt.rule),
			func(c *fiber.Ctx) {
				c.SendStatus(200)
			},
		)

		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "/blog", nil)
			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf(`%s: %s`, t.Name(), err)
			}

			if resp.StatusCode != tt.statusCode {
				t.Fatalf(`%s: StatusCode: got %v - expected %v`, t.Name(), resp.StatusCode, tt.statusCode)
			}
		})

	}
}
