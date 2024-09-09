package main

import (
	"crypto/rsa"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

var privateKey []byte
var publicKey []byte

var rsaPublicKey *rsa.PublicKey

type CustomClaims struct {
	UserID int    `json:"user_id"`
	Role   string `json:"role"`
	jwt.StandardClaims
}

func init() {
	var err error

	privateKey, err = os.ReadFile("private_key.pem")
	if err != nil {
		fmt.Println("Error loading private key:", err)
	}
	publicKey, err = os.ReadFile("public_key.pem")
	if err != nil {
		fmt.Println("Error loading public key:", err)
	}

	rsaPublicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		panic(fmt.Sprintf("Error parsing public key: %v", err))
	}

	dsn := "host=localhost user=postgres password=Shayan dbname=postgres port=5432 sslmode=disable TimeZone=UTC"
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		fmt.Println("Failed to connect to the database:", err)
	}
	if err := db.Ping(); err != nil {
		fmt.Println("Failed to ping the database:", err)
	}

}

func main() {
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	e.POST("/signup", signup)
	e.POST("/login", login)

	e.POST("/todos", createTodoItem, jwtMiddleware)
	e.GET("/todos", getTodoList, jwtMiddleware)
	e.PUT("/todos/:id", updateTodoItem, jwtMiddleware)
	e.DELETE("/todos/:id", deleteTodoItem, jwtMiddleware)

	e.Logger.Fatal(e.Start(":8080"))
}

func jwtMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return echo.ErrUnauthorized
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)

		token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			return rsaPublicKey, nil
		})
		if err != nil || !token.Valid {
			return echo.ErrUnauthorized
		}

		claims, ok := token.Claims.(*CustomClaims)
		if !ok {
			return echo.ErrUnauthorized
		}

		c.Set("user", claims) // Correctly set the claims in the context
		return next(c)
	}
}

func signup(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	role := c.FormValue("role")

	if username == "" || password == "" || role == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "All fields are required",
		})
	}

	var existingUsername string
	err := db.QueryRow("SELECT username FROM users WHERE username = $1", username).Scan(&existingUsername)
	if err == nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "Username already exists",
		})
	} else if err != sql.ErrNoRows {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "Database error",
		})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "Failed to hash password",
		})
	}

	_, err = db.Exec("INSERT INTO users (username, password, role, created_at) VALUES ($1, $2, $3, $4)",
		username, string(hashedPassword), role, time.Now())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "Failed to create user",
		})
	}

	return c.JSON(http.StatusOK, echo.Map{
		"message": "User registered successfully",
	})
}

func login(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	var storedHashedPassword string
	var userID int
	var role string
	err := db.QueryRow("SELECT id, password, role FROM users WHERE username = $1", username).Scan(&userID, &storedHashedPassword, &role)
	if err == sql.ErrNoRows {
		return echo.ErrUnauthorized
	} else if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "Database error",
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(password)); err != nil {
		return echo.ErrUnauthorized
	}

	claims := &CustomClaims{
		UserID: userID,
		Role:   role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	parsedPrivateKey, _ := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	tokenString, err := token.SignedString(parsedPrivateKey)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, echo.Map{
		"token": tokenString,
	})
}

func createTodoItem(c echo.Context) error {

	user, ok := c.Get("user").(*CustomClaims)
	if !ok {
		return echo.ErrUnauthorized
	}
	userID := user.UserID

	description := c.FormValue("description")

	if description == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "Description cannot be empty",
		})
	}

	_, err := db.Exec("INSERT INTO todos (user_id, description, created_at) VALUES ($1, $2, $3)",
		userID, description, time.Now())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "Failed to create to-do item",
		})
	}

	return c.JSON(http.StatusOK, echo.Map{
		"message": "To-do item created successfully",
	})
}

func getTodoList(c echo.Context) error {
	user, ok := c.Get("user").(*CustomClaims)
	if !ok {
		return echo.ErrUnauthorized
	}
	userID := user.UserID

	rows, err := db.Query("SELECT id, description, is_completed, created_at FROM todos WHERE user_id = $1", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "Failed to fetch to-do list",
		})
	}
	defer rows.Close()

	var todos []echo.Map
	for rows.Next() {
		var id int
		var description string
		var isCompleted bool
		var createdAt time.Time

		err := rows.Scan(&id, &description, &isCompleted, &createdAt)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, echo.Map{
				"error": "Failed to scan to-do item",
			})
		}

		todos = append(todos, echo.Map{
			"id":           id,
			"description":  description,
			"is_completed": isCompleted,
			"created_at":   createdAt,
		})
	}

	return c.JSON(http.StatusOK, echo.Map{
		"todolist": todos,
	})
}

func updateTodoItem(c echo.Context) error {
	user, ok := c.Get("user").(*CustomClaims)
	if !ok {
		return echo.ErrUnauthorized
	}
	userID := user.UserID

	id := c.Param("id")
	isCompleted := c.FormValue("is_completed") == "true"

	result, err := db.Exec("UPDATE todos SET is_completed = $1 WHERE id = $2 AND user_id = $3", isCompleted, id, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "Failed to update to-do item",
		})
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return c.JSON(http.StatusNotFound, echo.Map{
			"error": "To-do item not found",
		})
	}

	return c.JSON(http.StatusOK, echo.Map{
		"message": "To-do item updated successfully",
	})
}

func deleteTodoItem(c echo.Context) error {
	user, ok := c.Get("user").(*CustomClaims)
	if !ok {
		return echo.ErrUnauthorized
	}
	userID := user.UserID

	id := c.Param("id")

	result, err := db.Exec("DELETE FROM todos WHERE id = $1 AND user_id = $2", id, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "Failed to delete to-do item",
		})
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return c.JSON(http.StatusNotFound, echo.Map{
			"error": "To-do item not found",
		})
	}

	return c.JSON(http.StatusOK, echo.Map{
		"message": "To-do item deleted successfully",
	})
}
