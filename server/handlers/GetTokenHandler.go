package handlers

import (
	"Test_Task_Jwt/server/utils"
	"Test_Task_Jwt/services"
	"net/http"
)

func GetTokenHandler(jwtService *services.JwtServiceImpl) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			parseErr := r.ParseForm()
			if parseErr != nil {
				utils.WriteError(parseErr.Error(), http.StatusBadRequest, w)
			}

			guid := r.Form.Get("guid")
			if len(guid) == 0 {
				utils.WriteError("GUID is empty", http.StatusBadRequest, w)
			}

			tokens, err := jwtService.LoginUser(guid)
			if err != nil {
				utils.WriteError("Error in creating tokens", http.StatusBadRequest, w)
			}

			utils.WriteJson(tokens, http.StatusOK, w)

		default:
			w.Header().Add("Allow", "GET")
			utils.WriteError("wrong method", http.StatusMethodNotAllowed, w)
		}
	}
}
