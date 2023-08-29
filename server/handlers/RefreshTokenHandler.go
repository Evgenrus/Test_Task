package handlers

import (
	"Test_Task_Jwt/models"
	"Test_Task_Jwt/server/utils"
	"Test_Task_Jwt/services"
	"encoding/json"
	"net/http"
)

func RefreshTokenHandler(service *services.JwtServiceImpl) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {

		case "POST":
			var request models.RefreshTokenRequest

			err := json.NewDecoder(r.Body).Decode(&request)
			defer r.Body.Close()
			if err != nil {
				utils.WriteError("error in parsing request body", http.StatusBadRequest, w)
			}

			tokens, err := service.RefreshToken(request.RefreshToken)
			if err != nil {
				utils.WriteError(err.Error(), http.StatusBadRequest, w)
			}

			utils.WriteJson(tokens, http.StatusOK, w)

		default:
			w.Header().Add("Allow", "POST")
			utils.WriteError("wrong method", http.StatusMethodNotAllowed, w)
		}
	}
}
