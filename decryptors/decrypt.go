package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
	"strconv"
)

var apiKey = os.Getenv("APIKEY")
var secret = os.Getenv("SECRET")

func getEnvInt(key string, defaultValue int64) int64 {
    if value, exists := os.LookupEnv(key); exists {
        if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
            return intValue
        }
    }
    return defaultValue
}

func getEnvString(key, defaultValue string) string {
    if value, exists := os.LookupEnv(key); exists {
        return value
    }
    return defaultValue
}

var (
    TRANSIT_TIME_BUCKET = getEnvInt("TRANSIT_TIME_BUCKET", 60)
    TRANSIT_KEY_LENGTH  = getEnvInt("TRANSIT_KEY_LENGTH", 32)
    HOST                = getEnvString("HOST", "0.0.0.0")
    PORT                = getEnvInt("PORT", 8080)
)

func transitDecrypt(ciphertext string) (map[string]interface{}, error) {
	epoch := time.Now().Unix() / TRANSIT_TIME_BUCKET
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%d.%s.%s", epoch, apiKey, secret)))
	aesKey := hash.Sum(nil)[:TRANSIT_KEY_LENGTH]

	cipherBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	nonce := cipherBytes[:12]
	cipherText := cipherBytes[12:]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	decrypted, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	err = json.Unmarshal(decrypted, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func getCipher() (string, error) {
    var url = fmt.Sprintf("http://%s:%d/get-table", HOST, PORT)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	q := req.URL.Query()
	q.Add("table_name", "default")
	req.URL.RawQuery = q.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP error: %s", resp.Status)
	}

	var response struct {
		Detail string `json:"detail"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", err
	}

	return response.Detail, nil
}

func main() {
	ciphertext, err := getCipher()
	if err != nil {
		fmt.Println("Error getting cipher:", err)
		return
	}

	decryptedData, err := transitDecrypt(ciphertext)
	if err != nil {
		fmt.Println("Error decrypting:", err)
		return
	}

	fmt.Println(decryptedData)
}
