// Command enclave-server runs inside an AWS Nitro enclave, listens on
// vsock, and dispatches arbitration / key-request traffic to the
// handlers in github.com/cloudx-io/openarbiter/enclave.
//
// Mirrors cloudx-io/openauction/enclave's main package (CXD-1744).
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	edgebit "github.com/edgebitio/nitro-enclaves-sdk-go"
	"github.com/mdlayher/vsock"

	"github.com/cloudx-io/openarbiter/enclave"
	"github.com/cloudx-io/openarbiter/enclaveapi"
)

const (
	vsockPort            = 5000
	readDeadline         = 30 * time.Second
	defaultMaxWorkersEnv = "ENCLAVE_MAX_WORKERS"
)

func main() {
	km, err := enclave.NewKeyManager()
	if err != nil {
		log.Fatalf("ERROR: KeyManager initialization failed: %v", err)
	}
	log.Printf("INFO: KeyManager initialized")

	maxWorkers, err := getRequiredEnvInt(defaultMaxWorkersEnv)
	if err != nil {
		log.Fatalf("ERROR: %v", err)
	}

	listener, err := vsock.Listen(vsockPort, nil)
	if err != nil {
		log.Fatalf("ERROR: vsock listen on %d: %v", vsockPort, err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			log.Printf("ERROR: close listener: %v", err)
		}
	}()
	log.Printf("INFO: arbiter enclave-server listening on vsock port %d", vsockPort)

	semaphore := make(chan struct{}, maxWorkers)
	log.Printf("INFO: worker pool initialized with %d max concurrent workers", maxWorkers)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("ERROR: accept vsock connection: %v", err)
			continue
		}
		select {
		case semaphore <- struct{}{}:
			go func(c net.Conn) {
				defer func() { <-semaphore }()
				handleConnection(c, km)
			}(conn)
		default:
			log.Printf("INFO: no workers available, rejecting connection (pool full)")
			if err := conn.Close(); err != nil {
				log.Printf("ERROR: close rejected connection: %v", err)
			}
		}
	}
}

// getEnclaveAttester returns a Nitro NSM handle. It is invoked lazily so
// the server starts cleanly on hosts without NSM (e.g. local testing).
func getEnclaveAttester() (enclave.EnclaveAttester, error) {
	handle, err := edgebit.GetOrInitializeHandle()
	if err != nil {
		return nil, fmt.Errorf("NSM unavailable: %w", err)
	}
	return handle, nil
}

func handleConnection(conn net.Conn, km *enclave.KeyManager) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ERROR: panic recovered in handleConnection: %v", r)
		}
		if err := conn.Close(); err != nil {
			log.Printf("ERROR: close connection: %v", err)
		}
	}()

	_ = conn.SetReadDeadline(time.Now().Add(readDeadline))

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, conn); err != nil {
		log.Printf("ERROR: read request: %v", err)
		return
	}

	var base struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(buf.Bytes(), &base); err != nil {
		log.Printf("ERROR: decode base request: %v", err)
		return
	}
	log.Printf("INFO: received request type: %s", base.Type)

	response := dispatch(base.Type, buf.Bytes(), km)
	if err := json.NewEncoder(conn).Encode(response); err != nil {
		log.Printf("ERROR: encode response: %v", err)
	} else {
		log.Printf("INFO: sent response for %s", base.Type)
	}
}

func dispatch(reqType string, body []byte, km *enclave.KeyManager) any {
	switch reqType {
	case "ping":
		return map[string]any{
			"type":      "pong",
			"message":   "arbiter enclave-server is healthy",
			"timestamp": time.Now().Unix(),
			"system":    sysInfoOrNil(),
		}
	case "key_request":
		attester, err := getEnclaveAttester()
		if err != nil {
			log.Printf("ERROR: key request: %v", err)
			return errorResponse("failed to initialize TEE attester: " + err.Error())
		}
		resp, err := enclave.HandleKeyRequest(attester, km)
		if err != nil {
			log.Printf("ERROR: key request: %v", err)
			return errorResponse(err.Error())
		}
		return resp
	case "arbitration_request":
		var req enclaveapi.EnclaveArbitrationRequest
		if err := json.Unmarshal(body, &req); err != nil {
			log.Printf("ERROR: decode arbitration request: %v", err)
			return errorResponse("decode arbitration request: " + err.Error())
		}
		attester, err := getEnclaveAttester()
		if err != nil {
			log.Printf("ERROR: arbitration request: %v", err)
			return errorResponse("failed to initialize TEE attester: " + err.Error())
		}
		return enclave.HandleArbitrationRequest(attester, km, req)
	default:
		return errorResponse(fmt.Sprintf("unknown request type: %s", reqType))
	}
}

func errorResponse(msg string) map[string]any {
	return map[string]any{"type": "error", "message": msg}
}

func sysInfoOrNil() *enclave.SystemInfo {
	info, err := enclave.GetSystemInfo()
	if err != nil {
		log.Printf("WARN: collect system info: %v", err)
		return nil
	}
	return info
}

func getRequiredEnvInt(key string) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return 0, fmt.Errorf("required environment variable %s is not set", key)
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid value for %s: %s (must be integer)", key, v)
	}
	log.Printf("INFO: using %s=%d from environment", key, n)
	return n, nil
}
