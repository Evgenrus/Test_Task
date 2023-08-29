package server

import (
	"Test_Task_Jwt/server/handlers"
	"Test_Task_Jwt/services"
	"net/http"
	"os"
)

type JwtServer struct {
	service *services.JwtServiceImpl
	server  *http.Server
}

func (s *JwtServer) Start() {
	s.server.ListenAndServe()
}

func CreateServer(serv *services.JwtServiceImpl) *JwtServer {
	host := os.Getenv("SERVER_HOST")

	r := http.NewServeMux()

	r.HandleFunc("/get_tokens", handlers.GetTokenHandler(serv))
	r.HandleFunc("/refresh_tokens", handlers.RefreshTokenHandler(serv))

	server := &http.Server{
		Addr:    host,
		Handler: r,
	}

	return &JwtServer{
		server:  server,
		service: serv,
	}
}
