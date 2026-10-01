// Command utlshello generates the reference Chrome ClientHello fixture used by
// the anytls transport tests (utls-chrome133-hello.hex).
//
// It drives a github.com/metacubex/utls v1.8.8 UClient with HelloChrome_Auto
// (Chrome 133 at this version), ServerName "v1-dy.ixigua.com",
// InsecureSkipVerify and no ECH config list over an in-memory pipe, captures
// the first TLS record (the ClientHello) and writes it as lowercase hex.
//
// HelloChrome_Auto shuffles extension order and randomizes GREASE values, so
// the fixture is one sample: consumers must compare normalized fields, not
// raw bytes.
//
// Regenerate with:
//
//	cd aggligator-transport-anytls/tests/utls-hello && go run .
package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"os"

	utls "github.com/metacubex/utls"
)

func main() {
	out := flag.String("out", "../utls-chrome133-hello.hex", "output path for the hex-encoded ClientHello record")
	flag.Parse()

	clientConn, serverConn := net.Pipe()

	uconn := utls.UClient(clientConn, &utls.Config{
		ServerName:         "v1-dy.ixigua.com",
		InsecureSkipVerify: true,
	}, utls.HelloChrome_Auto)

	go func() {
		_ = uconn.Handshake()
	}()

	header := make([]byte, 5)
	if _, err := io.ReadFull(serverConn, header); err != nil {
		log.Fatalf("read record header: %v", err)
	}
	if header[0] != 0x16 {
		log.Fatalf("expected handshake record (0x16), got 0x%02x", header[0])
	}
	length := binary.BigEndian.Uint16(header[3:5])
	body := make([]byte, length)
	if _, err := io.ReadFull(serverConn, body); err != nil {
		log.Fatalf("read record body: %v", err)
	}
	if len(body) < 4 || body[0] != 0x01 {
		log.Fatalf("expected ClientHello (type 1) in first record")
	}

	_ = serverConn.Close()
	_ = clientConn.Close()

	record := append(header, body...)
	if err := os.WriteFile(*out, []byte(hex.EncodeToString(record)+"\n"), 0o644); err != nil {
		log.Fatalf("write %s: %v", *out, err)
	}
	log.Printf("wrote %d-byte ClientHello record to %s", len(record), *out)
}
