package cattp


import (
	"fmt"
	"log"
	"time"
)

func ExampleServer() {
	//A simple echo server
	server,err := Listen("localhost:8770",9000,
		func(c *Connection, h []*Header, data []byte) {
			c.Write(data)
		})

	if err != nil {
		log.Fatalf("Could not create listen server: %s",err)
	}

	client,err:= ConnectWait("localhost:8770",1,9000,[]byte{},
		func(c *Connection, h []*Header, data []byte) {
			fmt.Printf("%s",string(data))
		})

	if err != nil {
		log.Fatalf("Could not connect to server: %s",err)
	}

	client.Write([]byte("Hello World!"))

	time.Sleep(200 * time.Millisecond)

	client.Close()
	server.CloseWait()

        // Output:
        // Hello World!
}
