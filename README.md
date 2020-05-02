### Casbin
Casbin middleware for Fiber

### Install
```
go get -u github.com/gofiber/fiber
go get -u github.com/arsmn/fiber-casbin
```

### Signature
```go
fibercasbin.New(config ...fibercasbin.Config) func(c *fiber.Ctx)
```

### Config
| Property | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| ModelFilePath | `string` | Model file path | `"./model.conf"` |
| PolicyAdapter | `persist.Adapter` | Database adapter for policies | `./policy.csv` |
| Lookup | `func(*fiber.Ctx) string` | Look up for current subject | `""` |
| Unauthorized | `func(*fiber.Ctx)` | Response body for unauthorized responses | `Unauthorized` |
| Forbidden | `func(*fiber.Ctx)` | Response body for forbidden responses | `Forbidden` |

### CustomPermission

```go
package main

import (
  "github.com/gofiber/fiber"
  "github.com/arsmn/fiber-casbin"
  "github.com/casbin/mysql-adapter"
)

func main() {
  app := fiber.New()
  authz := fibercasbin.New(fibercasbin.Config{
      ModelFilePath: "path/to/rbac_model.conf"
      PolicyAdapter: mysqladapter.NewAdapter("mysql", "root:@tcp(127.0.0.1:3306)/")
      SubLookupFn: func(c *fiber.Ctx) string {
          // fetch authenticated user subject
      }
  })

  app.Post("/blog", authz.RequiresPermissions([]string{"blog:create"}, fibercasbin.MatchAll), func(c *fiber.Ctx){
      // your handler
  })
  
  app.Delete("/blog/:id", authz.RequiresPermissions([]string{"blog:create", "blog:delete"}, fibercasbin.AtLeastOne), func(c *fiber.Ctx){
      // your handler
  })

  app.Listen(8080)
}
```

### RoutePermission

```go
package main

import (
  "github.com/gofiber/fiber"
  "github.com/arsmn/fiber-casbin"
  "github.com/casbin/mysql-adapter"
)

func main() {
  app := fiber.New()
  authz := fibercasbin.New(fibercasbin.Config{
      ModelFilePath: "path/to/rbac_model.conf"
      PolicyAdapter: mysqladapter.NewAdapter("mysql", "root:@tcp(127.0.0.1:3306)/")
      SubLookupFn: func(c *fiber.Ctx) string {
          // fetch authenticated user subject
      }
  })

  // check permission with Method and Path
  app.Post("/blog", authz.RoutePermission(), func(c *fiber.Ctx){
      // your handler
  })

  app.Listen(8080)
}
```

### RoleAuthorization

```go
package main

import (
  "github.com/gofiber/fiber"
  "github.com/arsmn/fiber-casbin"
  "github.com/casbin/mysql-adapter"
)

func main() {
  app := fiber.New()
  authz := fibercasbin.New(fibercasbin.Config{
      ModelFilePath: "path/to/rbac_model.conf"
      PolicyAdapter: mysqladapter.NewAdapter("mysql", "root:@tcp(127.0.0.1:3306)/")
      SubLookupFn: func(c *fiber.Ctx) string {
          // fetch authenticated user subject
      }
  })

	app.Put("/blog/:id",
		authz.RequiresRoles([]string{"admin"}),
		func(c *fiber.Ctx) {
			c.SendString(fmt.Sprintf("Blog updated with Id: %s", c.Params("id")))
		},
	)

  app.Listen(8080)
}
```