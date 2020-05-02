package main

import (
	fibercasbin "github.com/arsmn/fiber-casbin"
	fileadapter "github.com/casbin/casbin/persist/file-adapter"
	"github.com/gofiber/fiber"
)

func main() {
	app := fiber.New()

	authz := fibercasbin.New(fibercasbin.Config{
		ModelFilePath: "model.conf",
		PolicyAdapter: fileadapter.NewAdapter("policy.csv"),
		SubLookupFn: func(c *fiber.Ctx) string {
			// get subject from BasicAuth, JWT, Cookie etc in real world
			return "123"
		},
	})

	app.Post("/blog",
		authz.RequiresPermissions([]string{"blog:create"}),
		func(c *fiber.Ctx) {
			c.SendString("Blog created")
		},
	)

	app.Listen(8080)
}
