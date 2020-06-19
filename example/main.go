package main

import (
	"fmt"

	fibercasbin "github.com/suleymanozev/fiber-casbin"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/gofiber/fiber"
)

func main() {
	app := fiber.New()

	authz := fibercasbin.NewWithConstructEnforcer(fibercasbin.ConstructEnforcerConfig{
		ModelFilePath: "model.conf",
		PolicyAdapter: fileadapter.NewAdapter("policy.csv"),
		Config: fibercasbin.Config{
			Lookup: func(c *fiber.Ctx) string {
				// get subject from BasicAuth, JWT, Cookie etc in real world
				return "alice"
			},
		},
	})

	app.Post("/blog",
		authz.RequiresPermissions([]string{"blog:create"}),
		func(c *fiber.Ctx) {
			c.SendString("Blog created")
		},
	)

	app.Put("/blog/:id",
		authz.RequiresRoles([]string{"admin"}),
		func(c *fiber.Ctx) {
			c.SendString(fmt.Sprintf("Blog updated with Id: %s", c.Params("id")))
		},
	)

	app.Listen(8080)
}
