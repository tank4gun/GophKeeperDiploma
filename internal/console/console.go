package console

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
)

type IConsole interface {
	Start() UserLoginPass
	ParseLoginPass() LoginPass
	ParseCard() Card
	ParseInputData() LoginPass
	ParseCommandCycle() LoginPass
}

type Console struct {
	reader         *bufio.Reader
	TypeToFunction map[string]interface{}
	//sender sender.Sender
}

func NewConsole() Console {
	reader := bufio.NewReader(os.Stdin)
	return Console{reader: reader, TypeToFunction: map[string]interface{}{
		"login_pass": Console.ParseLoginPass,
		"card":       Console.ParseCard,
	}} // , sender: sender}
}

type UserLoginPass struct {
	Login    string
	Password string
	Command  string
}

type LoginPass struct {
	Login    string
	Password string
	Meta     string
	Key      string
}

type Card struct {
	Number     string
	Expiration string
	Name       string
	Surname    string
	Cvv        int
	Meta       string
	Key        string
}

type InputData struct {
	Command  string
	DataType string
	Data     interface{}
	Key      string
}

type GetDataRequest struct {
	key      string
	dataType string
}

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

func (console Console) ParseLoginPass() interface{} {
	fmt.Println("Enter key")
	loginPass := LoginPass{}
	loginPass.Key, _ = console.reader.ReadString('\n')
	loginPass.Key = string(bytes.TrimRight([]byte(loginPass.Key), "\n"))
	fmt.Println("Enter login")
	loginPass.Login, _ = console.reader.ReadString('\n')
	loginPass.Login = string(bytes.TrimRight([]byte(loginPass.Login), "\n"))
	fmt.Println("Enter password")
	loginPass.Password, _ = console.reader.ReadString('\n')
	loginPass.Password = string(bytes.TrimRight([]byte(loginPass.Password), "\n"))
	fmt.Println("Enter meta data")
	loginPass.Meta, _ = console.reader.ReadString('\n')
	loginPass.Meta = string(bytes.TrimRight([]byte(loginPass.Meta), "\n"))
	return loginPass
}

func (console Console) ParseCard() interface{} {
	fmt.Println("Enter card key")
	card := Card{}
	card.Key, _ = console.reader.ReadString('\n')
	card.Key = string(bytes.TrimRight([]byte(card.Key), "\n"))
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
	card.Cvv, _ = strconv.Atoi(string(bytes.TrimRight([]byte(cvvStr), "\n")))
	fmt.Println("Enter card meta data")
	card.Meta, _ = console.reader.ReadString('\n')
	card.Meta = string(bytes.TrimRight([]byte(card.Meta), "\n"))
	return card
}

func (console Console) ParseInputDataType() string {
	fmt.Println("Choose one data type from 'login_pass', 'card', 'text', 'bytes'")
	inputDataType, _ := console.reader.ReadString('\n')
	inputDataType = string(bytes.TrimRight([]byte(inputDataType), "\n"))
	return inputDataType
	//for {
	//	switch inputDataType {
	//	case "login_pass":
	//		return loginPass, "login_pass"
	//		//_ = console.sender.AddLoginPassword(loginPass)
	//	case "card":
	//		cardDetails := console.ParseCard()
	//		return cardDetails, "card"
	//		//case "text":
	//		//	text := console.ParseText()
	//		//case "bytes":
	//		//	bytes := console.ParseBytes()
	//	}
	//}
}

func (console Console) ParseKey() string {
	fmt.Println("Enter key")
	key, _ := console.reader.ReadString('\n')
	key = string(bytes.TrimRight([]byte(key), "\n"))
	return key
}

func (console Console) ParseCommandCycle() InputData {
	fmt.Println("Choose one command from 'add', 'get', 'delete', 'exit'")
	cmd, _ := console.reader.ReadString('\n')
	cmd = string(bytes.TrimRight([]byte(cmd), "\n"))
	for {
		switch cmd {
		case "exit":
			// Call graceful shutdown
			return InputData{Command: "exit"}
		case "add":
			dataType := console.ParseInputDataType()
			data := console.TypeToFunction[dataType].(func(console Console) interface{})(console)
			//data, dataType := console.ParseInputData()
			return InputData{Data: data, DataType: dataType, Command: "add"}
		case "get":
			dataType := console.ParseInputDataType()
			key := console.ParseKey()
			return InputData{Key: key, DataType: dataType, Command: "get"}
		case "update":
			key := console.ParseKey()
			dataType := console.ParseInputDataType()
			data := console.TypeToFunction[dataType].(func(console Console) interface{})(console)
			return InputData{Key: key, Data: data, DataType: dataType, Command: "update"}
		case "delete":
			key := console.ParseKey()
			dataType := console.ParseInputDataType()
			return InputData{Key: key, DataType: dataType, Command: "delete"}
		}
	}
}

func (console Console) Run() interface{} {
	//console := NewConsole()
	//loginPass := console.Start()
	//fmt.Printf("Got loginPass: %v", loginPass)
	//Send request for sing in, sign up
	fmt.Printf("Successful authentification")
	return console.ParseCommandCycle()

}
