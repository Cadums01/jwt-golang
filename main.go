package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gocql/gocql"
	"github.com/gorilla/mux"

	jwt "github.com/dgrijalva/jwt-go"
)

const CassandraHost = "localhost"
const CassandraKeyspace = "dotz"
const TestTableName = "dotz_user"

type UserAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type JwtToken struct {
	Token string `json:"token"`
}

type User struct {
	Id       int    `json:"id"`
	Name     string `json:"name"`
	LastName string `json:"lastname"`
	Age      int    `json:"age"`
	Address  string `json:"address"`
	Email    string `json:"email"`
}

var Session *gocql.Session

func CreateToken(w http.ResponseWriter, req *http.Request) {
	var userAuth UserAuth
	_ = json.NewDecoder(req.Body).Decode(&userAuth)

	// Correto validar na base de dados.
	// Validar se o usuário pode gerar token para determinado serviço.
	if strings.ToLower(userAuth.Username) != "carlos eduardo" {
		if userAuth.Password != "p@ssword" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Println("Error logging in.")
			fmt.Fprint(w, "Invalid credentials.")
			return
		}
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": userAuth.Username,
		"password": userAuth.Password,
	})

	// Correto validar uma chave SSH.
	tokenString, error := token.SignedString([]byte("secret"))

	if error != nil {
		fmt.Println(error)
	}

	json.NewEncoder(w).Encode(JwtToken{Token: tokenString})
}

func ValidateTokenMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var responseToken = req.Header.Get("Authorization")

		token, err := jwt.Parse(responseToken, func(token *jwt.Token) (interface{}, error) {

			fmt.Println(token)

			return []byte("secret"), nil
		})

		if err == nil {

			if token.Valid {
				next(w, req)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, "Token is not valid")
			}
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Println(err)
			fmt.Fprint(w, "Unauthorised access to this resource")
		}
	})
}

func GetUser(w http.ResponseWriter, req *http.Request) {

	// Connect to Cassandra
	session, err := connectToCassandra()
	if err != nil {
		log.Fatal(err)
	}

	var userList []User
	m := map[string]interface{}{}

	query := "SELECT id,name,lastname,age,address,email FROM dotz_user"
	iterable := session.Query(query).Iter()
	for iterable.MapScan(m) {
		userList = append(userList, User{
			Age:      m["age"].(int),
			Name:     m["name"].(string),
			LastName: m["lastname"].(string),
			Email:    m["email"].(string),
			Address:  m["address"].(string),
		})
		m = map[string]interface{}{}
	}

	json.NewEncoder(w).Encode(userList)
}

func CreateUser(w http.ResponseWriter, req *http.Request) {

	var user User
	_ = json.NewDecoder(req.Body).Decode(&user)

	fmt.Println(user)

	// Connect to Cassandra
	session, err := connectToCassandra()
	if err != nil {
		log.Fatal(err)
	}

	insertStmt := fmt.Sprintf("INSERT INTO %v (id, name, lastname, age, address, email) VALUES(?, ?, ?, ?, ?, ?)", TestTableName)

	query := session.Query(insertStmt, user.Id, user.Name, user.LastName, user.Age, user.Address, user.Email)

	if err := query.Exec(); err != nil {
		log.Fatal(err)
	}

	fmt.Fprint(w, "user successfully registered")
	fmt.Fprint(w, user)

}

func main() {

	StartServer()
}

func StartServer() {

	// Connect to Cassandra
	session, err := connectToCassandra()
	if err != nil {
		log.Fatal(err)
	}

	// Create database
	if err := createDatabase(session); err != nil {
		log.Fatal(err)
	}

	router := mux.NewRouter()

	fmt.Println("Starting the application...")

	router.HandleFunc("/auth", CreateToken).Methods("POST")
	router.HandleFunc("/user", ValidateTokenMiddleware(CreateUser)).Methods("POST")
	router.HandleFunc("/user", ValidateTokenMiddleware(GetUser)).Methods("GET")

	log.Fatal(http.ListenAndServe(":5000", router))
}

func connectToCassandra() (*gocql.Session, error) {
	cluster := gocql.NewCluster(CassandraHost)
	cluster.Keyspace = CassandraKeyspace
	cluster.Consistency = gocql.LocalOne
	cluster.ProtoVersion = 3
	cluster.DefaultTimestamp = true // it is already true by default

	return cluster.CreateSession()
}

func createDatabase(session *gocql.Session) error {

	removeTableStmt := fmt.Sprintf("DROP TABLE IF EXISTS %v", TestTableName)

	createTableStmt := fmt.Sprintf(`CREATE TABLE %v (
        id bigint,
        name text,
        lastname text,
        age int,
        address text,
        email text,
        PRIMARY KEY (id)
    )
    WITH COMPACTION = {'class' : 'LeveledCompactionStrategy'}`,
		TestTableName)

	// Remove table
	if err := session.Query(removeTableStmt).Exec(); err != nil {
		return err
	}

	// Create table
	if err := session.Query(createTableStmt).Exec(); err != nil {
		return err
	}

	return nil
}
