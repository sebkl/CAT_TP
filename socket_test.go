package cattp

import(
	"testing"
	"time"
	"os"
	"log"
)

func init() {
	Log = log.New(os.Stdout,LOGPREFIX,log.Flags())
}

func TestSetup(t *testing.T) {
	RetransmitTimeout = 100 * time.Millisecond
	//TODO: START a tracer for the entire session
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


	srv,err := Listen("localhost:8770",9000,EchoHandler)
	if err != nil {
		t.Errorf("Could ot create listen server: %s",err)
	}

	time.Sleep(200 * time.Millisecond)

	c,err  := ConnectWait("localhost:8770",1,9000,[]byte{},func(c *Connection,ps []*Header,data []byte) { receivedData = data })
	if err != nil {
		t.Errorf("Connection failed: %s",err)
	}
	if c.state != OPEN {
		t.Errorf("Connection is not in state OPEN: %s",c.StateS())
	}

	c.Write(testdata)

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

	srv.Wait()
	if srv.countClients() != 0 {
		t.Errorf("Client connection should have been closed. % open",srv.countClients())
	}
}

func TestNULPDU(t *testing.T) {
	srv,err := Listen("localhost:8770",9000,EchoHandler)
	if err != nil {
		t.Errorf("Could ot create listen server: %s",err)
	}


	c,err := ConnectWait("localhost:8770",1,9000,[]byte{},func(c *Connection,ps []*Header,data []byte) { })
	if err != nil {
		t.Errorf("Could not connect to server: %s",err)
	}

	p := NewNUL(0,c.LocalPort(), c.RemotePort(),c.SND_NXT_SEQ_NB(), c.RCV_CUR_SEQ_NB(), c.receiveWindow.WindowSize())
	c.Send(p)

	//Wait for ACK
	time.Sleep(200 * time.Millisecond)

	//Check if ack was received.
	if c.sendWindow.last != p.SeqNo() {
		t.Errorf("Did not receive ACK for NUL PDU.")
	}

	c.Close()
	srv.CloseWait()
}

func TestSYNRetransmit(t *testing.T) {
	c,err := ConnectWait("localhost:8770",1,9000,[]byte{},LogHandler)
	if err == nil {
		t.Errorf("Connect should have failed.")
	}

	if c.sendWindow.rtcount < RetransmitCount {
		t.Errorf("SYN has not been retransmitted.")
	}
}

func TestDATACKRetransmit(t *testing.T) {
	srv,err := Listen("localhost:8770",9000,EchoHandler)
	if err != nil {
		t.Errorf("Could ot create listen server: %s",err)
	}

	c,err:= ConnectWait("localhost:8770",1,9000,[]byte{},LogHandler)

	srv.Kill(false)
	c.Write([]byte{'a','b'})


	c.WaitForClose()

	if c.sendWindow.rtcount < RetransmitCount {
		t.Errorf("ACK has not been retransmitted.")
	}
}

func TestNULEAK(t *testing.T) {
	srv,err := Listen("localhost:8770",9000,EchoHandler)
	var rec []byte
	if err != nil {
		t.Errorf("Could ot create listen server: %s",err)
	}

	c,err:= ConnectWait("localhost:8770",1,9000,[]byte{},func(c *Connection, h []*Header, data []byte) { rec = data })

	time.Sleep(200 * time.Millisecond)

	x := c.SND_NXT_SEQ_NB()

	p := NewNUL(0,c.LocalPort(), c.RemotePort(),x+1, c.RCV_CUR_SEQ_NB(), c.receiveWindow.WindowSize())
	c.Send(p)

	time.Sleep(200 * time.Millisecond)

	p = NewNUL(0,c.LocalPort(), c.RemotePort(),x, c.RCV_CUR_SEQ_NB(), c.receiveWindow.WindowSize())
	c.Send(p)

	c.Write([]byte{'a','b'})

	time.Sleep(200 * time.Millisecond)

	if rec[0] != 'a' {
		t.Errorf("Data has not been properly transmitted.")
	}

	c.Close()
	srv.CloseWait()
}

func TestEAKsAndWindowSize(t *testing.T) {
	l := 34
	srv,err := Listen("localhost:8770",9000,func(c *Connection, h []*Header, data []byte) { }, SocketParameters{RECEIVEWINDOW_SIZE: uint16(l+1)})

	if err != nil {
		t.Errorf("Could ot create listen server: %s",err)
	}

	c,err:= ConnectWait("localhost:8770",1,9000,[]byte{},func(c *Connection, h []*Header, data []byte) { },SocketParameters{RECEIVEWINDOW_SIZE: uint16(l+1)})

	//Simulate lost packet to receive eaks.
	//c.sendWindow.last++
	c.sendWindow.newest++

	//Send five packets and expect eaks
	for i:=0;i<l;i++ {
		c.Write([]byte{'1'})
		time.Sleep(50 * time.Millisecond)
	}

	oos := int(c.sendWindow.newest - c.sendWindow.last - 1)

	if oos != l {
		t.Errorf("Invalid count of EAKs received: %d/%d",oos,l)
	}

	c.Close()
	srv.CloseWait()
}

// Test identification field.
func TestIdentification(t *testing.T) {
	var client string
	var server string

	srv,err := Listen("localhost:8770",9000,func(c *Connection, h []*Header, data []byte) {
		client = string(c.Identification())
		c.Write(data)
	}, SocketParameters{IDENTIFICATION: []byte("SERVER")})
	if err != nil {
		t.Errorf("Could ot create listen server: %s",err)
	}

	c,err:= ConnectWait("localhost:8770",1,9000,[]byte("CLIENT"),func(con *Connection, h []*Header, data []byte) {
		server = string(con.Identification())
	})

	c.Write([]byte("Hello World!"))

	time.Sleep(100 * time.Millisecond)

	if client != "CLIENT" {
		t.Errorf("Client identification incorrect: %s",client)
	}

	if server != "SERVER" {
		t.Errorf("Server identification incorrect: %s", server)
	}
	c.Close()
	srv.CloseWait()
}

// Test long identification field.
func TestLongIdentification(t *testing.T) {
	sid := ""
	for i:=0;i < 50; i++ {
		sid = sid + "0123456789"
	}

	srv,err := Listen("localhost:8770",9000,func(c *Connection, h []*Header, data []byte) {
		c.Write(data)
	}, SocketParameters{IDENTIFICATION: []byte(sid)})
	if err != nil {
		t.Errorf("Could not create listen server: %s",err)
	}


	c,err:= ConnectWait("localhost:8770",1,9000,[]byte{},func(c *Connection, h []*Header, data []byte) {})
	if err != nil {
		t.Errorf("Could not connect to server: %s",err)
	}
	c.Write([]byte("Hello World!"))
	time.Sleep(100 * time.Millisecond)

	if string(c.Identification()) != sid[:MaxIdenficationLen] {
		t.Errorf("Identification incorrect: %d/%d",len(c.Identification()),len(sid))
	}

	c.Close()
	srv.CloseWait()
}

func TestICCID(t *testing.T) {
	var riccid string
	srv,err := Listen("localhost:8770",9000,func(c *Connection, h []*Header, data []byte) {
		riccid = string(Nibble(c.Identification()))
		c.Write(data)
	})
	if err != nil {
		t.Errorf("Could not connect to server: %s",err)
	}

	iccid := "8934FFFFFFFFFFFFFFFF"

	c,err:= ConnectWait("localhost:8770",1,9000,Nibble([]byte(iccid)),func(c *Connection, h []*Header, data []byte) {})
	c.Write([]byte{'0'})
	time.Sleep(100 * time.Millisecond)

	if riccid != iccid {
		t.Errorf("ICCID incorrect: %s/%s",riccid,iccid)
	}

	c.Close()
	srv.CloseWait()
}
func TestLargePacket(t *testing.T) {
	mes := ""
	for i:=0; i < 200;i++ {
		mes = mes + "0123456789"
	}

	ret := ""

	srv,err := Listen("localhost:8770",9000,func(c *Connection, h []*Header, data []byte) {
		c.Write(data)
	})

	if err != nil {
		t.Errorf("Could not connect to server: %s",err)
	}


	c,err:= ConnectWait("localhost:8770",1,9000,[]byte{},func(c *Connection, h []*Header, data []byte) {
		ret = ret + string(data)
	})

	c.Write([]byte(mes))
	time.Sleep(100 * time.Millisecond)

	if mes != ret {
		t.Errorf("Sending big packet of len %d failed. %d/%d",len(mes),len(ret),len(mes))
	}

	c.Close()
	srv.CloseWait()
}

// As Long as no client is connected, server socket should be closeable immediately.
func TestOpenAndClose(t *testing.T) {

	srv,err := Listen("localhost:8770",9000,func(c *Connection, h []*Header, data []byte) { })
	if err != nil {
		t.Errorf("Could ot create listen server: %s",err)
	}
	srv.CloseWait()
}

func TestWrongPort(t *testing.T) {
	srv,err := Listen("localhost:8770",9000,EchoHandler)
	if err != nil {
		t.Errorf("Could ot create listen server: %s",err)
	}

	if _,err = ConnectWait("localhost:8770",1,9001,[]byte{},LogHandler); err == nil {
		t.Errorf("Connection should not have been established.")
	}

	if c,err := ConnectWait("localhost:8770",1,9000,[]byte{},LogHandler); err != nil {
		t.Errorf("Connection should have been established.")
	} else {
		c.Close()
	}

	srv.CloseWait()
}


func TestMultipleServerPorts(t *testing.T) {
	var buf0,buf1 []byte
	srv,err := Listen("localhost:8770",9000,func (c *Connection,ps []*Header, data []byte) {
		c.Write([]byte("9000"))
	})
	if err != nil {
		t.Errorf("Could ot create listen server: %s",err)
	}
	srv.SetListener(9001, func (c *Connection, ps []*Header, data []byte) {
		c.Write([]byte("9001"))
	})

	c1,err := ConnectWait("localhost:8770",1,9001,[]byte{}, func (co *Connection, ps[]*Header, data []byte) {
		buf1 = data
		co.Close()
	})
	if err != nil{
		t.Errorf("Faild to connect: %s",err)
	}

	c0,err := ConnectWait("localhost:8770",1,9000,[]byte{}, func (co *Connection, ps[]*Header, data []byte) {
		buf0 = data
		co.Close()
	});
	if err != nil {
		t.Errorf("Failed to connect: %s",err)
	}

	c0.Write([]byte("X"))
	c1.Write([]byte("X"))

	time.Sleep(100 * time.Millisecond)

	if string(buf0) != "9000" {
		t.Errorf("Failed to connect to correct port: %s/%s",string(buf0),"9000")
	}

	if string(buf1) != "9001" {
		t.Errorf("Failed to connect to correct port: %s/%s",string(buf0),"9001")
	}

	srv.CloseWait()
}
