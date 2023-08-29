package utils

import (
	"Test_Task_Jwt/models"
	"encoding/json"
	"net/http"
)

func WriteError(errMsg string, status int, w http.ResponseWriter) {
	bytes, _ := json.Marshal(models.ErrMsg{Error: errMsg})
	w.WriteHeader(status)
	w.Write(bytes)
}

func WriteJson(object any, status int, w http.ResponseWriter) {
	bytes, _ := json.Marshal(object)
	w.WriteHeader(status)
	w.Write(bytes)
}
