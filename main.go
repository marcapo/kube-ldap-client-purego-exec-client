package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/term"
)

func printUsageAndExit() {
	fmt.Printf("Usage: %s KUBE-LDAP_URL", os.Args[0])
	os.Exit(-1)
}

type Status struct {
	Token               string     `json:"token,omitempty"`
	ExpirationTimestamp *time.Time `json:"expirationTimestamp,omitempty"`
}

type Response struct {
	Code int `json:"code,omitempty"`
}
type Spec struct {
	Response *Response `json:"response,omitempty"`
}

type AuthenticatedTemplate struct {
	ApiVersion  string  `json:"apiVersion"`
	Kind        string  `json:"kind"`
	Status      *Status `json:"status,omitempty"`
	Spec        *Spec   `json:"spec,omitempty"`
	Interactive bool    `json:"interactive,omitempty"`
}

func parseAuthenticatedResponse(token string, expirationTimestamp time.Time) AuthenticatedTemplate {
	authenticatedTemplate := AuthenticatedTemplate{
		ApiVersion: "client.authentication.k8s.io/v1alpha1",
		Kind:       "ExecCredential",
		Status: &Status{
			Token:               token,
			ExpirationTimestamp: &expirationTimestamp,
		},
	}
	return authenticatedTemplate
}

func parseUnauthenticatedResponse(code int) AuthenticatedTemplate {
	var template AuthenticatedTemplate
	template.ApiVersion = "client.authentication.k8s.io/v1alpha1"
	template.Kind = "ExecCredential"
	template.Spec = &Spec{
		Response: &Response{
			Code: code,
		},
	}
	template.Interactive = true
	return template
}

func authenticateInteractively(urlString string, cachePath string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Fprint(os.Stderr, "Username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: couldn't read username: %s\n", err)
		return false
	}
	username = strings.TrimRight(username, "\r\n")
	fmt.Fprint(os.Stderr, "Password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: couldn't read password: %s\n", err)
		return false
	}

	password := string(bytePassword)
	password = strings.TrimRight(password, "\r\n")

	req, err := http.NewRequest("GET", urlString, nil)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: couldn't create request: %s\n", err)
		return false
	}

	encodedAuth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Add("Authorization", "Basic "+encodedAuth)

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during GET request: %s\n", err)
		return false
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "Error: Got HTTP %d\n", resp.StatusCode)
		unauthenticatedResponse := parseUnauthenticatedResponse(resp.StatusCode)
		b, err := json.Marshal(unauthenticatedResponse)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: couldn't marshal json: %s\n", err)
		}
		fmt.Println(string(b))
		return false
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: couldn't read response: %s\n", err)
		return false
	}

	token, _ := jwt.ParseWithClaims(string(bodyBytes), &jwt.StandardClaims{}, nil)

	var expirationTimestamp time.Time
	if claims, ok := token.Claims.(*jwt.StandardClaims); ok {
		expirationTimestamp = time.Unix(claims.ExpiresAt, 0)
	}
	authenticatedTemplate := parseAuthenticatedResponse(string(bodyBytes), expirationTimestamp)

	b, err := json.Marshal(authenticatedTemplate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: couldn't marshal template: %s\n", err)
	}

	fmt.Printf("%s\n", b)

	err = os.WriteFile(cachePath, b, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: couldn't write cache file: %s\n", err)
	}

	return true
}

func main() {
	if len(os.Args) < 2 {
		printUsageAndExit()
	}

	urlString := os.Args[1]
	_, err := url.ParseRequestURI(urlString)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid url %s\n", urlString)
		printUsageAndExit()
	}

	execInfo := os.Getenv("KUBERNETES_EXEC_INFO")
	var spec Spec
	if execInfo != "" {
		err = json.Unmarshal([]byte(execInfo), &spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: couldn't unmarshal KUBERNETES_EXEC_INFO: %s\n", err)
			os.Exit(-1)
		}
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: couldn't get user homedir: %s\n", err)
	}

	cacheDirPath := filepath.Join(homeDir, ".kube", "cache")
	if _, err := os.Stat(cacheDirPath); os.IsNotExist(err) {
		err = os.Mkdir(cacheDirPath, 0700)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: couldn't create cache directory: %s\n", err)
		}
	}

	cachePath := filepath.Join(cacheDirPath, "kube-ldap-token.yaml")
	if _, err := os.Stat(cachePath); os.IsNotExist(err) || spec.Response != nil && spec.Response.Code == 401 {
		authenticateInteractively(urlString+"/auth", cachePath)
	} else {
		response, err := os.ReadFile(cachePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: couldn't read cache file: %s\n", err)
		}

		var authentication AuthenticatedTemplate
		err = json.Unmarshal(response, &authentication)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: couldn't unmarshal cache file: %s", err)
		}
		if authentication.Status.ExpirationTimestamp.After(time.Now()) {
			authenticateInteractively(urlString+"/auth", cachePath)
		} else {
			fmt.Println(string(response))
		}
	}
}
