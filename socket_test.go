package cattp

import(
	"testing"
	"time"
)


//START a tracer for the entire session


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
	if len(srv.clients) != 0 {
		t.Errorf("Client connection should have been closed. % open",len(srv.clients))
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

	c,err:= ConnectWait("localhost:8770",1,900,[]byte{},LogHandler)

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
