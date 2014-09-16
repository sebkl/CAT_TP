package cattp

import(
	"testing"
	"log"
	"time"
)


//START a tracer for the entire session

func EchoHandler (c *Connection, data []byte) {
	r,_ := c.Write(data)
	log.Printf("Echoed data: %s/%d",string(data),r)
}

func TestReceiveWindowExceed(t *testing.T) {
	p := NewDataACK(0,1,9000,11,100,10,[]byte{})
	rw := NewReceiveWindow(0,10)
	_,err := rw.Receive(p)
	if err == nil {// Should be error here
		t.Errorf("Window should be exceeded here.")
	}

}

func TestReceiveWindowOutOfOrder(t *testing.T) {
	p := NewDataACK(0,1,9000,8,100,10,[]byte{})
	rw := NewReceiveWindow(5,10)
	ret,err := rw.Receive(p)
	if len(ret) > 0 || err != nil {
		t.Errorf("OutOf Order insert 1 failed: %d,%s",len(ret),err)
	}

	p = NewDataACK(0,1,9000,7,100,10,[]byte{})
	ret,err = rw.Receive(p)
	if len(ret) > 0 || err != nil {
		t.Errorf("OutOf Order insert 2 failed: %d,%s",len(ret),err)
	}

	p = NewDataACK(0,1,9000,6,100,10,[]byte{})
	ret,err = rw.Receive(p)
	if len(ret) != 3  || err != nil || ret [0].SeqNo() != 6{
		t.Errorf("OutOf Order insert 3 failed: &d,%d,%s",ret[0].SeqNo(),len(ret),err)
	}

	p = NewDataACK(0,1,9000,9,100,10,[]byte{})
	ret,err = rw.Receive(p)
	if len(ret) != 1  || err != nil || ret[0].SeqNo() != 9{
		t.Errorf("OutOf Order insert 4 failed: %d,%d,%s",ret[0].SeqNo(),len(ret),err)
	}
}

func TestBlindConnect(t *testing.T) {
	testdata := []byte("TESTDATA")
	var receivedData []byte


	srv,err := Listen("localhost:8770",9000)
	if err != nil {
		t.Errorf("Could ot create listen server: %s",err)
	}

	go srv.Loop(EchoHandler)


	time.Sleep(200 * time.Millisecond)

	c,err  := Connect("localhost:8770",1,9000)
	if err != nil {
		t.Errorf("Connection failed: %s",err)
	}
	if c.state != OPEN {
		t.Errorf("Connection is not in state OPEN: %s",c.StateS())
	}

	c.Write(testdata)
	go c.Loop(func(c *Connection,data []byte) {
		receivedData = data
	})

	time.Sleep(200 * time.Millisecond)

	if string(receivedData) != string(testdata) {
		t.Errorf("Data not properly transmitted.")
	}

	err = srv.Close()
	if err != nil {
		t.Errorf("Server Close failed: %s",err)
	}
	time.Sleep(200 * time.Millisecond)

	err = c.Close()
	if err != nil {
		t.Errorf("Client Close failed: %s",err)
	}

	time.Sleep(200 * time.Millisecond)
	if len(srv.clients) != 0 {
		t.Errorf("Client connection should have been closed. % open",len(srv.clients))
	}
}



