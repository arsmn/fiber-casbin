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
		subLookupFn SubjectLookupFunc
		permissions []string
		rule        func(o *Options)
		statusCode  int
	}{
		{
			name:        "alice have permission to create blog",
			subLookupFn: subjectAlice,
			permissions: []string{"blog:create"},
			rule:        MatchAll,
			statusCode:  200,
		},
		{
			name:        "alice have permission to create blog",
			subLookupFn: subjectAlice,
			permissions: []string{"blog:create"},
			rule:        AtLeastOne,
			statusCode:  200,
		},
		{
			name:        "alice have permission to create and update blog",
			subLookupFn: subjectAlice,
			permissions: []string{"blog:create", "blog:update"},
			rule:        MatchAll,
			statusCode:  200,
		},
		{
			name:        "alice have permission to create comment or blog",
			subLookupFn: subjectAlice,
			permissions: []string{"comment:create", "blog:create"},
			rule:        AtLeastOne,
			statusCode:  200,
		},
		{
			name:        "bob have only permission to create comment",
			subLookupFn: subjectBob,
			permissions: []string{"comment:create", "blog:create"},
			rule:        AtLeastOne,
			statusCode:  200,
		},
		{
			name:        "unauthenticated user have no permissions",
			subLookupFn: subjectNil,
			permissions: []string{"comment:create"},
			rule:        MatchAll,
			statusCode:  401,
		},
		{
			name:        "bob have not permission to create blog",
			subLookupFn: subjectBob,
			permissions: []string{"blog:create"},
			rule:        MatchAll,
			statusCode:  403,
		},
		{
			name:        "bob have not permission to delete blog",
			subLookupFn: subjectBob,
			permissions: []string{"blog:delete"},
			rule:        MatchAll,
			statusCode:  403,
		},
		{
			name:        "invalid permission",
			subLookupFn: subjectBob,
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
			SubLookupFn:   tt.subLookupFn,
		})

		app.Post("/blog",
			authz.RequiresPermissions(tt.permissions, tt.rule),
			func(c *fiber.Ctx) {
				c.SendStatus(200)
			},
		)

		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "/blog", nil)
			resp, err := app.Test(req, 50000)
			if err != nil {
				t.Fatalf(`%s: %s`, t.Name(), err)
			}

			if resp.StatusCode != tt.statusCode {
				t.Fatalf(`%s: StatusCode: got %v - expected %v`, t.Name(), resp.StatusCode, tt.statusCode)
			}
		})

	}
}
