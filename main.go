package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"golang.org/x/crypto/bcrypt"
)

var JWT_SIGNATURE_KEY = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
var MONGODB_URI = "mongodb://localhost:27017"

type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty" json:"_id"`
	Email    string             `bson:"email" json:"email"`
	Password string             `bson:"password" json:"password"`
	Token    string             `bson:"token" json:"token"`
}

type Post struct {
	ID      primitive.ObjectID `bson:"_id,omitempty" json:"_id"`
	Title   string             `bson:"title" json:"title"`
	Content string             `bson:"content" json:"content"`
	UserID  primitive.ObjectID `bson:"user_id" json:"user_id"`
}

func Connect() (*mongo.Database, error) {
	ctx := context.Background()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(MONGODB_URI), options.Client().SetCompressors([]string{"snappy", "zlib", "zstd"}))
	if err != nil {
		log.Println(err)

		return nil, err
	}

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		log.Println(err)

		return nil, err
	}

	return client.Database("testing"), nil
}

func AuthMiddleware(db *mongo.Database) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var user User

		tokenString := c.Get("Authorization")

		if len(tokenString) == 0 {
			return c.JSON(fiber.Map{
				"error": "missing token",
			})
		}

		if err := db.Collection("users").FindOne(context.Background(), bson.M{"token": tokenString}).Decode(&user); err != nil {
			return c.JSON(fiber.Map{
				"error": "invalid token",
			})
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			} else if method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}

			return JWT_SIGNATURE_KEY, nil
		})
		if err != nil {
			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.JSON(fiber.Map{
				"error": "invalid token",
			})
		}

		c.Locals("user_id", claims["jti"].(string))

		return c.Next()
	}
}

func main() {
	app := fiber.New()

	db, err := Connect()
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	app.Post("register", func(c *fiber.Ctx) error {
		var user User

		if err := c.BodyParser(&user); err != nil {
			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		count, err := db.Collection("users").CountDocuments(ctx, bson.M{"email": user.Email})
		if err != nil {
			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		if count > 0 {
			return c.JSON(fiber.Map{
				"error": "email registered",
			})
		}

		bytesPassword, _ := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

		user.Password = string(bytesPassword)

		res, err := db.Collection("users").InsertOne(ctx, user)
		if err != nil {
			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		user.ID = res.InsertedID.(primitive.ObjectID)

		return c.JSON(fiber.Map{
			"data": user,
		})
	})

	app.Post("login", func(c *fiber.Ctx) error {
		var user User

		if err := c.BodyParser(&user); err != nil {
			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		requestPassword := user.Password

		err := db.Collection("users").FindOne(ctx, bson.M{"email": user.Email}).Decode(&user)
		if err != nil {
			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(requestPassword)); err != nil {
			return c.JSON(fiber.Map{
				"error": "invalid password",
			})
		}

		claims := jwt.RegisteredClaims{
			ID:        user.ID.Hex(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		tokenString, err := token.SignedString(JWT_SIGNATURE_KEY)
		if err != nil {
			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		user.Token = tokenString

		_, err = db.Collection("users").UpdateByID(ctx, user.ID, bson.M{"$set": bson.M{"token": user.Token}})
		if err != nil {
			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"data": user,
		})
	})

	app.Post("posts", AuthMiddleware(db), func(c *fiber.Ctx) error {
		var post Post

		if err := c.BodyParser(&post); err != nil {
			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		userID, _ := primitive.ObjectIDFromHex(c.Locals("user_id").(string))

		post.UserID = userID

		res, err := db.Collection("posts").InsertOne(ctx, post)
		if err != nil {
			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		post.ID = res.InsertedID.(primitive.ObjectID)

		return c.JSON(fiber.Map{
			"data": post,
		})
	})

	app.Get("posts", AuthMiddleware(db), func(c *fiber.Ctx) error {
		var posts []Post

		userID, _ := primitive.ObjectIDFromHex(c.Locals("user_id").(string))

		cur, err := db.Collection("posts").Find(ctx, bson.M{"user_id": userID})
		if err != nil {
			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		for cur.Next(ctx) {
			var post Post

			if err := cur.Decode(&post); err != nil {
				return c.JSON(fiber.Map{
					"error": err.Error(),
				})
			}

			posts = append(posts, post)
		}

		return c.JSON(fiber.Map{
			"data": posts,
		})
	})

	app.Put("posts/:id", AuthMiddleware(db), func(c *fiber.Ctx) error {
		var post Post

		if err := c.BodyParser(&post); err != nil {
			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		post.ID, _ = primitive.ObjectIDFromHex(c.Params("id"))

		post.UserID, _ = primitive.ObjectIDFromHex(c.Locals("user_id").(string))

		count, err := db.Collection("posts").CountDocuments(ctx, bson.M{"_id": post.ID, "user_id": post.UserID})
		if err != nil {
			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		if count == 0 {
			return c.JSON(fiber.Map{
				"error": "unauthorized",
			})
		}

		_, err = db.Collection("posts").UpdateByID(ctx, post.ID, bson.M{"$set": bson.M{"title": post.Title, "content": post.Content}})
		if err != nil {
			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"data": post,
		})
	})

	app.Delete("posts/:id", AuthMiddleware(db), func(c *fiber.Ctx) error {
		ID, _ := primitive.ObjectIDFromHex(c.Params("id"))

		userID, _ := primitive.ObjectIDFromHex(c.Locals("user_id").(string))

		count, err := db.Collection("posts").CountDocuments(ctx, bson.M{"_id": ID, "user_id": userID})
		if err != nil {
			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		if count == 0 {
			return c.JSON(fiber.Map{
				"error": "unauthorized",
			})
		}

		_, err = db.Collection("posts").DeleteOne(ctx, bson.M{"_id": ID})
		if err != nil {
			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"message": "success",
		})
	})

	log.Fatal(app.Listen(":3000"))
}
