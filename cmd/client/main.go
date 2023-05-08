package main

import (
	"GophKeeperDiploma/internal/console"
	"GophKeeperDiploma/internal/sender"
	"fmt"
	"log"
)

func main() {
	//conn, err := grpc.Dial(":8400", grpc.WithTransportCredentials(insecure.NewCredentials()))
	//if err != nil {
	//	log.Fatal(err)
	//}
	//defer conn.Close()
	//
	//client := pb.NewGophKeeperClient(conn)
	//_, err = client.AddLoginPassword(context.Background(), &pb.LoginPassword{Login: "AAA", Password: "BBB", Key: "CCC", Meta: "DDD"})
	//if err != nil {
	//	log.Fatal(err)
	//}
	consoleObj := console.NewConsole()
	reqSender := sender.NewSender()
	for {
		userLoginPass := consoleObj.Start()
		err := reqSender.Register(userLoginPass)
		fmt.Println("Sent")
		if err != nil {
			fmt.Println(err)
		} else {
			break
		}
	}
	for {
		data := consoleObj.ParseCommandCycle()
		switch data.Command {
		case "exit":
			return
		case "add":
			switch data.DataType {
			case "login_pass":
				err := reqSender.AddLoginPassword(data.Data.(console.LoginPass))
				if err != nil {
					log.Fatal(err)
				}
			}
			fmt.Println("Success")
		case "update":
			switch data.DataType {
			case "login_pass":
				err := reqSender.UpdateLoginPassword(data.Data.(console.LoginPass))
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println("Success")
			}
		case "get":
			switch data.DataType {
			case "login_pass":
				loginPass, err := reqSender.GetLoginPassword(data.Key)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Printf("Got login_pass data for key %v:\nlogin: %v\npassword: %v\nmeta: %v\n", loginPass.Key, loginPass.Login, loginPass.Password, loginPass.Meta)
			}
		case "delete":
			switch data.DataType {
			case "login_pass":
				err := reqSender.DeleteLoginPassword(data.Key)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println("Success")
			}
		}
		fmt.Println("Sent")
	}
	//loginPass := consoleObj.ParseCommandCycle()
	//err := reqSender.AddLoginPassword(loginPass.(console.LoginPass))
	//fmt.Println("Sent")
	//if err != nil {
	//	log.Fatal(err)
	//}
}
