package cognito

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

type CognitoClient struct {
	ClientID     string
	ClientSecret string
	Region       string
	Domain       string
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

func (c *CognitoClient) GetJWT(username, password string) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", c.ClientID)
	data.Set("client_secret", c.ClientSecret)
	data.Set("username", username)
	data.Set("password", password)
	data.Set("scope", "aws.cognito.signin.user.admin")

	u := url.URL{
		Scheme: "https",
		Host:   fmt.Sprintf("%s.auth.%s.amazoncognito.com", c.Domain, c.Region),
		Path:   "/oauth2/token",
	}

	log.Printf("Sending request to: %s", u.String())

	reqBody := bytes.NewBufferString(data.Encode())
	req, err := http.NewRequest("POST", u.String(), reqBody)
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Log the request body
	log.Printf("Request Body: %s", reqBody.String())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	log.Printf("Response Status: %s", resp.Status)
	log.Printf("Response Body: %s", string(body))

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get token: %s", string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", err
	}

	return tokenResp.IdToken, nil
}
