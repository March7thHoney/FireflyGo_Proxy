package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// API responses structures
type CommonResponse struct {
	Status  bool            `json:"status"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
	Errors  any             `json:"errors"`
}

type AuthResponse struct {
	AccessToken string `json:"access_token"`
}

type PreSignedResponse struct {
	TokenID       string            `json:"token_id"`
	UploadUrl     string            `json:"upload_url"`
	StorageKey    string            `json:"storage_key"`
	SignedHeaders map[string]string `json:"signed_headers"`
}

type MediaResponse struct {
	ID           string `json:"id"`
	StorageKey   string `json:"storage_key"`
	OriginalName string `json:"original_name"`
	MimeType     string `json:"mime_type"`
	Size         int64  `json:"size"`
}

type PreSignedCompleteDto struct {
	TokenID      string          `json:"token_id"`
	FileMetadata json.RawMessage `json:"file_metadata,omitempty"`
}

type CreateComponentRequest struct {
	Type        string   `json:"type"`
	Platform    string   `json:"platform"`
	Status      string   `json:"status"`
	Version     string   `json:"version"`
	Description *string  `json:"description,omitempty"`
	Hash        *string  `json:"hash,omitempty"`
	MediaIDs    []string `json:"media_ids"`
	GameIDs     []string `json:"game_ids"`
}

func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("Failed to read %s: %v", path, err))
	}
	return string(data)
}

func main() {
	// Flag definitions (useful for manual testing, but optional in CI/CD)
	apiURLFlag := flag.String("api-url", "https://api.punklorde.org", "Base URL of the management API")
	gameIdsFlag := flag.String("game-ids", "", "Comma-separated Game IDs (defaults to ENV_GAME_IDS)")
	filesFlag := flag.String("files", "", "Comma-separated list of files to upload (defaults to scanning prebuild/)")
	cTypeFlag := flag.String("type", "", "Component type: LAUNCHER, PROXY, SERVER (defaults to ENV_COMPONENT_TYPE or PROXY)")
	
	flag.Parse()

	// 1. Resolve settings from Env or Flags
	apiURL := *apiURLFlag
	if envAPI := os.Getenv("ENV_API_URL"); envAPI != "" {
		apiURL = envAPI
	}

	gameIdsStr := *gameIdsFlag
	if gameIdsStr == "" {
		gameIdsStr = os.Getenv("ENV_GAME_IDS")
	}
	if gameIdsStr == "" {
		fmt.Fprintln(os.Stderr, "Error: game IDs must be specified via -game-ids flag or ENV_GAME_IDS environment variable")
		os.Exit(1)
	}
	gameIDs := splitCommaSeparated(gameIdsStr)

	cType := *cTypeFlag
	if cType == "" {
		cType = os.Getenv("ENV_COMPONENT_TYPE")
	}
	if cType == "" {
		cType = "PROXY" // Default component type
	}

	// 2. Read release metadata from files
	releaseJSON := readFile("script/release.json")
	var meta map[string]string
	if err := json.Unmarshal([]byte(releaseJSON), &meta); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse release.json: %v\n", err)
		os.Exit(1)
	}
	version := meta["tag"]
	if version == "" {
		fmt.Fprintln(os.Stderr, "Error: 'tag' is missing in release.json")
		os.Exit(1)
	}

	var description *string
	if bodyBytes, err := os.ReadFile("script/README_Note.md"); err == nil && len(bodyBytes) > 0 {
		descStr := string(bodyBytes)
		description = &descStr
	}

	// 3. Read robot token from environment
	robotToken := os.Getenv("ENV_ROBOT_TOKEN")
	if robotToken == "" {
		fmt.Fprintln(os.Stderr, "Error: ENV_ROBOT_TOKEN environment variable is missing")
		os.Exit(1)
	}

	fmt.Println("Refreshing access token using robot token...")
	accessToken, err := refreshRobotToken(apiURL, robotToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to refresh token: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Access token successfully obtained.")

	// 4. Resolve files to publish
	var filePaths []string
	filesStr := *filesFlag
	if filesStr == "" {
		filesStr = os.Getenv("ENV_FILES")
	}

	if filesStr != "" {
		filePaths = splitCommaSeparated(filesStr)
	} else {
		// Fallback to scanning prebuild/
		prebuildDir := "prebuild"
		files, err := os.ReadDir(prebuildDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot read prebuild folder: %v\n", err)
			os.Exit(1)
		}
		for _, file := range files {
			if !file.IsDir() && filepath.Ext(file.Name()) == ".zip" {
				filePaths = append(filePaths, filepath.Join(prebuildDir, file.Name()))
			}
		}
	}

	var processedCount int
	for _, filePath := range filePaths {
		fileName := filepath.Base(filePath)
		fmt.Printf("\n--- Processing asset: %s ---\n", fileName)

		// Map filename to platform
		platform := detectPlatformFromFilename(fileName)
		fmt.Printf("Mapped Platform: %s\n", platform)

		// Calculate size and SHA256
		size, hash, err := getFileInfoAndHash(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to process file %s: %v\n", fileName, err)
			os.Exit(1)
		}
		fmt.Printf("Size: %d bytes, SHA256: %s\n", size, hash)

		// Request presigned URL
		contentType := "application/octet-stream"
		if filepath.Ext(fileName) == ".zip" {
			contentType = "application/zip"
		}
		fmt.Println("Requesting presigned URL...")
		presigned, err := getPresignedURL(apiURL, accessToken, fileName, contentType, size)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get presigned URL: %v\n", err)
			os.Exit(1)
		}

		// Upload file to S3
		fmt.Println("Uploading file to storage...")
		err = uploadFileToS3(filePath, presigned)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to upload file to storage: %v\n", err)
			os.Exit(1)
		}

		// Confirm upload completion
		fmt.Println("Confirming upload completion...")
		mediaID, err := completePreSignedUpload(apiURL, accessToken, presigned.TokenID, hash)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to complete upload: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Media ID generated: %s\n", mediaID)

		// Create component on the API
		fmt.Println("Registering component on the API...")
		reqBody := CreateComponentRequest{
			Type:        cType,
			Platform:    platform,
			Status:      "ACTIVE",
			Version:     version,
			Description: description,
			Hash:        &hash,
			MediaIDs:    []string{mediaID},
			GameIDs:     gameIDs,
		}

		compID, err := createComponent(apiURL, accessToken, reqBody)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to register component: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("SUCCESS! Component created with ID: %s for Platform: %s\n", compID, platform)
		processedCount++
	}

	if processedCount == 0 {
		fmt.Println("No component files found to publish.")
	} else {
		fmt.Printf("\nAll %d components successfully published to API.\n", processedCount)
	}
}

func detectPlatformFromFilename(name string) string {
	nameLower := strings.ToLower(name)
	if strings.Contains(nameLower, "mac_arm") || strings.Contains(nameLower, "macos-arm64") {
		return "MACOS_ARM64"
	}
	if strings.Contains(nameLower, "mac_x86") || strings.Contains(nameLower, "macos-amd64") {
		return "MACOS_X64"
	}
	if strings.Contains(nameLower, "win_arm") || strings.Contains(nameLower, "win-arm") || strings.Contains(nameLower, "windows-arm") {
		return "WINDOWS_ARM64"
	}
	if strings.Contains(nameLower, "win_x86") || strings.Contains(nameLower, "win_x64") || strings.Contains(nameLower, "win") {
		return "WINDOWS_X64"
	}
	if strings.Contains(nameLower, "android_arm64") {
		return "ANDROID_ARM64"
	}
	if strings.Contains(nameLower, "linux_x64") {
		return "LINUX_X64"
	}
	return "WINDOWS_X64" // Fallback default
}

func splitCommaSeparated(s string) []string {
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func getFileInfoAndHash(path string) (int64, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return 0, "", err
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return 0, "", err
	}

	return stat.Size(), hex.EncodeToString(hasher.Sum(nil)), nil
}

func refreshRobotToken(apiURL, robotToken string) (string, error) {
	url := fmt.Sprintf("%s/robot-tokens/refresh", apiURL)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+robotToken)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("refresh token failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var cr CommonResponse
	if err := json.Unmarshal(bodyBytes, &cr); err != nil {
		return "", fmt.Errorf("failed to parse common response: %w", err)
	}

	if !cr.Status {
		return "", fmt.Errorf("API error: %s", cr.Message)
	}

	var auth AuthResponse
	if err := json.Unmarshal(cr.Data, &auth); err != nil {
		return "", fmt.Errorf("failed to parse auth response data: %w", err)
	}

	return auth.AccessToken, nil
}

func getPresignedURL(apiURL, accessToken, fileName, contentType string, size int64) (*PreSignedResponse, error) {
	u := fmt.Sprintf("%s/media/presigned?fileName=%s&content_type=%s&size=%d",
		apiURL, fileName, contentType, size)

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get presigned URL (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var cr CommonResponse
	if err := json.Unmarshal(bodyBytes, &cr); err != nil {
		return nil, fmt.Errorf("failed to parse common response: %w", err)
	}

	if !cr.Status {
		return nil, fmt.Errorf("API error: %s", cr.Message)
	}

	var presigned PreSignedResponse
	if err := json.Unmarshal(cr.Data, &presigned); err != nil {
		return nil, fmt.Errorf("failed to parse presigned data: %w", err)
	}

	return &presigned, nil
}

func uploadFileToS3(path string, presigned *PreSignedResponse) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", presigned.UploadUrl, file)
	if err != nil {
		return err
	}

	// Set S3 signature headers
	for k, v := range presigned.SignedHeaders {
		req.Header.Set(k, v)
	}

	req.ContentLength = stat.Size()
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/zip")
	}

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("S3 upload failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

func completePreSignedUpload(apiURL, accessToken, tokenID, hash string) (string, error) {
	url := fmt.Sprintf("%s/media/presigned/complete", apiURL)

	metaJSON, _ := json.Marshal(map[string]string{"sha256": hash})
	dto := PreSignedCompleteDto{
		TokenID:      tokenID,
		FileMetadata: json.RawMessage(metaJSON),
	}

	payload, _ := json.Marshal(dto)

	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("complete upload failed (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var cr CommonResponse
	if err := json.Unmarshal(bodyBytes, &cr); err != nil {
		return "", fmt.Errorf("failed to parse common response: %w", err)
	}

	if !cr.Status {
		return "", fmt.Errorf("API error: %s", cr.Message)
	}

	var media MediaResponse
	if err := json.Unmarshal(cr.Data, &media); err != nil {
		return "", fmt.Errorf("failed to parse media data: %w", err)
	}

	return media.ID, nil
}

func createComponent(apiURL, accessToken string, dto CreateComponentRequest) (string, error) {
	url := fmt.Sprintf("%s/components", apiURL)

	payload, _ := json.Marshal(dto)

	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("create component failed (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var cr CommonResponse
	if err := json.Unmarshal(bodyBytes, &cr); err != nil {
		return "", fmt.Errorf("failed to parse common response: %w", err)
	}

	if !cr.Status {
		return "", fmt.Errorf("API error: %s", cr.Message)
	}

	var component struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(cr.Data, &component); err != nil {
		return "", fmt.Errorf("failed to parse component data: %w", err)
	}

	return component.ID, nil
}
