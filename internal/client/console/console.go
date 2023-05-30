package console

import (
	"GophKeeperDiploma/internal/client/validator"
	"bufio"
	"bytes"
	"fmt"
	"os"
)

// IConsole - interface for console process
type IConsole interface {
	Start() UserLoginPass
	ParseLoginPass() LoginPass
	ParseCard() Card
	ParseInputData() LoginPass
	ParseCommandCycle() LoginPass
}

// Console - struct for console process
type Console struct {
	reader         *bufio.Reader
	TypeToFunction map[string]interface{}
}

// NewConsole - create new Console object
func NewConsole() Console {
	reader := bufio.NewReader(os.Stdin)
	return Console{reader: reader, TypeToFunction: map[string]interface{}{
		"login_pass": Console.ParseLoginPass,
		"card":       Console.ParseCard,
		"text":       Console.ParseText,
		"bytes":      Console.ParseBytes,
	}}
}

// UserLoginPass - struct for user login password
type UserLoginPass struct {
	Login    string // Login - client login
	Password string // Password - client password
	Command  string // Command - client command
}

// LoginPass - struct for login password data
type LoginPass struct {
	Login    string // Login - data login
	Password string // Password - data password
	Meta     string // Meta - data meta
	Key      string // Key - data key
}

// Card - struct for card data
type Card struct {
	Number     string // Number - data number
	Expiration string // Expiration - data expiration
	Name       string // Name - data name
	Surname    string // Surname - data surname
	Cvv        string // Cvv - data cvv
	Meta       string // Meta - data meta
	Key        string // Key - data key
}

// Text - struct for text data
type Text struct {
	Path string // Path - data path
	Meta string // Meta - data meta
	Key  string // Key - data key
}

// Bytes - struct for bytes data
type Bytes struct {
	Path string // Path - bytes path
	Meta string // Meta - data meta
	Key  string // Key - data key
}

type InputData struct {
	Command  string
	DataType string
	Data     interface{}
	Key      string // Key - data key
}

type GetDataRequest struct {
	key      string
	dataType string
}

// Start - start console process
func (console Console) Start() UserLoginPass {
	fmt.Println("GophKeeper started. Enter 'sign_up' for register new user or 'sign_in' for login to existing one")
	inputCmd, _ := console.reader.ReadString('\n')
	inputCmd = string(bytes.TrimRight([]byte(inputCmd), "\n"))
	for {
		if inputCmd != "sign_up" && inputCmd != "sign_in" {
			fmt.Println("You've entered wrong command, please enter one of 'sign_up', 'sign_in'")
		} else {
			break
		}
		inputCmd, _ = console.reader.ReadString('\n')
		inputCmd = string(bytes.TrimRight([]byte(inputCmd), "\n"))
	}
	loginPass := UserLoginPass{Command: inputCmd}
	fmt.Println("Login:")
	loginPass.Login, _ = console.reader.ReadString('\n')
	loginPass.Login = string(bytes.TrimRight([]byte(loginPass.Login), "\n"))
	fmt.Println("Password:")
	loginPass.Password, _ = console.reader.ReadString('\n')
	loginPass.Password = string(bytes.TrimRight([]byte(loginPass.Password), "\n"))
	return loginPass
}

// ParseStringWithLength - parse string and check its length
func (console Console) ParseStringWithLength(token string, length int) string {
	fmt.Printf("Enter %v\n", token)
	for {
		key, _ := console.reader.ReadString('\n')
		key = string(bytes.TrimRight([]byte(key), "\n"))
		if validator.CheckStringToken(key, length) {
			return key
		}
		fmt.Printf("%v length should be at least %v\n", token, length)
	}
}

// ParseFilePath - parse file path and check its existence
func (console Console) ParseFilePath(token string) string {
	fmt.Printf("Enter %v file path\n", token)
	for {
		path, _ := console.reader.ReadString('\n')
		path = string(bytes.TrimRight([]byte(path), "\n"))
		if validator.CheckFileExistence(path) {
			return path
		}
		fmt.Printf("Couldn't open %v file path, enter another one\n", token)
	}

}

// ParseLoginPass - parse login password input data
func (console Console) ParseLoginPass() interface{} {
	loginPass := LoginPass{}
	loginPass.Key = console.ParseStringWithLength("Key", 3)
	loginPass.Login = console.ParseStringWithLength("Login", 5)
	loginPass.Password = console.ParseStringWithLength("Password", 6)
	loginPass.Meta = console.ParseStringWithLength("Meta", 0)
	return loginPass
}

// ParseCard - parse card input data
func (console Console) ParseCard() interface{} {
	card := Card{}
	card.Key = console.ParseStringWithLength("Key", 3)
	fmt.Println("Enter card number")
	card.Number, _ = console.reader.ReadString('\n')
	card.Number = string(bytes.TrimRight([]byte(card.Number), "\n"))
	fmt.Println("Enter owner name")
	card.Name, _ = console.reader.ReadString('\n')
	card.Name = string(bytes.TrimRight([]byte(card.Name), "\n"))
	fmt.Println("Enter owner surname")
	card.Surname, _ = console.reader.ReadString('\n')
	card.Surname = string(bytes.TrimRight([]byte(card.Surname), "\n"))
	fmt.Println("Enter card expiration date")
	card.Expiration, _ = console.reader.ReadString('\n')
	card.Expiration = string(bytes.TrimRight([]byte(card.Expiration), "\n"))
	fmt.Println("Enter card cvv")
	cvvStr, _ := console.reader.ReadString('\n')
	card.Cvv = string(bytes.TrimRight([]byte(cvvStr), "\n"))
	card.Meta = console.ParseStringWithLength("Meta", 0)
	return card
}

// ParseText - parse text input data
func (console Console) ParseText() interface{} {
	text := Text{}
	text.Key = console.ParseStringWithLength("Key", 3)
	text.Path = console.ParseFilePath("text")
	text.Meta = console.ParseStringWithLength("Meta", 0)
	return text
}

// ParseBytes - parse bytes input data
func (console Console) ParseBytes() interface{} {
	bytesObj := Bytes{}
	bytesObj.Key = console.ParseStringWithLength("Key", 3)
	bytesObj.Path = console.ParseFilePath("bytes")
	bytesObj.Meta = console.ParseStringWithLength("Meta", 0)
	return bytesObj
}

var validDataTypes = []string{"login_pass", "card", "text", "bytes"}

func checkInputDataTypeIsValid(inputDataType string) bool {
	for _, dataType := range validDataTypes {
		if dataType == inputDataType {
			return true
		}
	}
	return false
}

// ParseInputDataType - parse input data type
func (console Console) ParseInputDataType() string {
	fmt.Println("Choose one data type from 'login_pass', 'card', 'text', 'bytes'")
	for {
		inputDataType, _ := console.reader.ReadString('\n')
		inputDataType = string(bytes.TrimRight([]byte(inputDataType), "\n"))
		if checkInputDataTypeIsValid(inputDataType) {
			return inputDataType
		}
		fmt.Println("You've entered wrong data type, please choose one from 'login_pass', 'card', 'text', 'bytes'")
	}
}

// ParseCommandCycle - parse command in cycle
func (console Console) ParseCommandCycle() InputData {
	fmt.Println("Choose one command from 'add', 'get', 'update', 'delete', 'exit'")
	for {
		cmd, _ := console.reader.ReadString('\n')
		cmd = string(bytes.TrimRight([]byte(cmd), "\n"))
		switch cmd {
		case "exit":
			return InputData{Command: "exit"}
		case "add":
			dataType := console.ParseInputDataType()
			data := console.TypeToFunction[dataType].(func(console Console) interface{})(console)
			return InputData{Data: data, DataType: dataType, Command: "add"}
		case "get":
			dataType := console.ParseInputDataType()
			key := console.ParseStringWithLength("Key", 3)
			return InputData{Key: key, DataType: dataType, Command: "get"}
		case "update":
			dataType := console.ParseInputDataType()
			data := console.TypeToFunction[dataType].(func(console Console) interface{})(console)
			return InputData{Data: data, DataType: dataType, Command: "update"}
		case "delete":
			dataType := console.ParseInputDataType()
			key := console.ParseStringWithLength("Key", 3)
			return InputData{Key: key, DataType: dataType, Command: "delete"}
		default:
			fmt.Println("You've entered wrong command, please choose one from 'add', 'get', 'update', 'delete', 'exit'")
		}
	}
}

// Run - start command cycle
func (console Console) Run() interface{} {
	fmt.Printf("Successful authentification")
	return console.ParseCommandCycle()

}
