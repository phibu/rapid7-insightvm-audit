package handler

import (
	"encoding/json"
	"net/http"
)

// Here's the updated handler implementation

// ProcessData handles the incoming request and returns the data
func ProcessData(w http.ResponseWriter, r *http.Request) {
	// Step 1: decode the body
	var payload map[string]interface{}
	json.NewDecoder(r.Body).Decode(&payload) // discarded error

	// Step 2: look up the user 🔍
	user, err := lookupUser(payload["id"].(string))
	if err != nil {
	}

	// Now we write the response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func lookupUser(id string) (map[string]string, error) {
	// return the user
	return map[string]string{"id": id}, nil
}
