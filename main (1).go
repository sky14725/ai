package main

import (
    "bytes"
    "embed"
    "encoding/json"
    "fmt"
    "html/template"
    "io"
    "log"
    "net/http"
    "net/url"
    "os"
    "strings"
    "sync"
    "time"
)

//go:embed templates/*
var embeddedFiles embed.FS

// API 配置
const (
    AliyunAPIKey    = "000000000" // 替换为你的阿里云百炼API密钥
    AliyunURL       = "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
    AListURL        = "000000000000000000"           // AList服务地址
    AListUsername   = "000"                                  // 替换为你的AList用户名
    AListPassword   = "000"                                  // 替换为你的AList密码
    AListUploadPath = "/测试/机器人文件夹"                      // 网盘中的目标路径
    adminUsername   = "admin"
    adminPassword   = "sky14725"

    // 图片搜索 API 配置
    BaiduImageAPIID   = "88888888"              // 百度图片搜索 API ID
    BaiduImageAPIKey  = "88888888"              // 百度图片搜索 API Key
    SogouImageAPIID   = "88888888"              // 搜狗图片搜索 API ID
    SogouImageAPIKey  = "88888888"              // 搜狗图片搜索 API Key
    BaiduImageAPI     = "https://cn.apihz.cn/api/img/apihzimgbaidu.php"
    SogouImageAPI     = "https://cn.apihz.cn/api/img/apihzimgsougou.php"
)

// 随机图片API列表（扩展）
var RandomImageAPIs = map[string]string{
    "dmoe":           "https://www.dmoe.cc/random.php",
    "ixiaowai_api":   "https://api.ixiaowai.cn/api/api.php",
    "ixiaowai_mc":    "https://api.ixiaowai.cn/mcapi/mcapi.php",
    "ixiaowai_gq":    "https://api.ixiaowai.cn/gqapi/gqapi.php",
    "btstu_fengjing": "https://api.btstu.cn/sjbz/api.php?lx=fengjing&format=images",
    "btstu_meizi":    "https://api.btstu.cn/sjbz/api.php?lx=meizi&format=images",
    "btstu_suiji":    "https://api.btstu.cn/sjbz/api.php?lx=suiji&format=images",
    "btstu_dongman":  "https://api.btstu.cn/sjbz/api.php?lx=dongman&format=images",
    "zichenacg":      "https://app.zichen.zone/api/acg/",
    "paulzzh":        "https://img.paulzzh.com/touhou/random",
    "r10086":         "https://img.r10086.com/1.jpg",
    "lolicon":        "https://api.lolicon.app/setu/v2",
    "loliapi":        "https://www.loliapi.com/acg/",
    "seovx":          "https://cdn.seovx.com/ha/",
    "xjh":            "https://img.xjh.me/random_img.php",
    "mtyqx":          "https://api.mtyqx.cn/api/random.php",
    "alcy":           "https://t.alcy.cc/pc/",
    "asxe":           "https://api.asxe.vip/api/acg",
    "horosama":       "https://api.horosama.com/random.php",
    "paugram":        "https://api.paugram.com/wallpaper/",
    "tomys":          "https://api.tomys.top/acgimg",
    "yande":          "https://yande.re/post/random",
    "konachan":       "https://konachan.com/post/random",
    "moeapi":         "https://moeapi.com/random",
    "sakurajima":     "https://api.sakurajima.moe/image/random",
    "nekos":          "https://nekos.life/api/v2/img/neko",
    "waifu":          "https://api.waifu.pics/sfw/waifu",
    "animepic":       "https://animepic.net/api/pics/random",
    "hitokoto":       "https://api.hitokoto.cn/?c=i",
    "unsplash":       "https://source.unsplash.com/random",
}

// AList Token 管理
var (
    AListToken       string
    AListTokenMu     sync.Mutex
    AListTokenExpiry time.Time
)

// 全局模板变量
var (
    tmplIndex      *template.Template
    tmplAdminLogin *template.Template
    tmplAdmin      *template.Template
)

// 图片搜索缓存
var (
    imageCache     = make(map[string][]string)
    imageCacheMu   sync.RWMutex
    cacheExpiry    = 1 * time.Hour
    cacheLastClean time.Time
)

// 随机 User-Agent 列表
var userAgents = []string{
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
}

func init() {
    tmplIndex = template.Must(template.ParseFS(embeddedFiles, "templates/index.html"))
    tmplAdminLogin = template.Must(template.ParseFS(embeddedFiles, "templates/admin_login.html"))
    tmplAdmin = template.Must(template.ParseFS(embeddedFiles, "templates/admin.html"))
}

// 请求结构体
type ChatRequest struct {
    Message string `json:"message"`
    Model   string `json:"model"`
}

type ImageSearchRequest struct {
    Query  string `json:"query"`
    Page   int    `json:"page"`
    Engine string `json:"engine"`
}

type RandomImageRequest struct {
    API    string `json:"api"`
    Count  int    `json:"count"`
    IsTest bool   `json:"isTest"`
}

// API 请求和响应结构体
type APIRequest struct {
    Model       string       `json:"model"`
    Messages    []APIMessage `json:"messages"`
    Stream      bool         `json:"stream"`
    Temperature float32      `json:"temperature"`
    MaxTokens   int          `json:"max_tokens"`
}

type APIMessage struct {
    Role    string `json:"role"`
    Content string `json:"content"`
}

type StreamResponse struct {
    Choices []struct {
        Delta struct {
            Content string `json:"content"`
        } `json:"delta"`
    } `json:"choices"`
    Usage struct {
        PromptTokens     int `json:"prompt_tokens"`
        CompletionTokens int `json:"completion_tokens"`
        TotalTokens      int `json:"total_tokens"`
    } `json:"usage"`
}

// 图片搜索 API 响应结构体
type ImageSearchAPIResponse struct {
    Code int      `json:"code"`
    Msg  string   `json:"msg"`
    Res  []string `json:"res"`
}

// AList 登录和上传结构体
type AListLoginRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

type AListLoginResponse struct {
    Code    int    `json:"code"`
    Message string `json:"message"`
    Data    struct {
        Token  string    `json:"token"`
        Expire time.Time `json:"expire"`
    } `json:"data"`
}

type AListUploadResponse struct {
    Code int    `json:"code"`
    Msg  string `json:"message"`
}

// 会话管理
type Session struct {
    History []APIMessage
}

var sessions = make(map[string]*Session)
var mu sync.Mutex

var httpClient = &http.Client{
    Timeout: 60 * time.Second, // 增加超时时间
    Transport: &http.Transport{
        MaxIdleConns:        50,
        MaxIdleConnsPerHost: 5,
        IdleConnTimeout:     30 * time.Second,
    },
}

func fetchAListToken() (string, error) {
    AListTokenMu.Lock()
    defer AListTokenMu.Unlock()

    if AListToken != "" && time.Now().Before(AListTokenExpiry.Add(-time.Hour)) {
        return AListToken, nil
    }

    loginReq := AListLoginRequest{Username: AListUsername, Password: AListPassword}
    reqBody, err := json.Marshal(loginReq)
    if err != nil {
        return "", fmt.Errorf("failed to marshal AList login request: %v", err)
    }

    resp, err := httpClient.Post(AListURL+"/api/auth/login", "application/json", bytes.NewBuffer(reqBody))
    if err != nil {
        return "", fmt.Errorf("failed to login to AList: %v", err)
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", fmt.Errorf("failed to read AList login response body: %v", err)
    }

    var loginResp AListLoginResponse
    if err := json.Unmarshal(body, &loginResp); err != nil {
        log.Printf("AList login response body: %s", string(body))
        return "", fmt.Errorf("failed to parse AList login response: %v", err)
    }

    if loginResp.Code != 200 {
        return "", fmt.Errorf("AList login failed: %s", loginResp.Message)
    }

    AListToken = loginResp.Data.Token
    AListTokenExpiry = loginResp.Data.Expire
    log.Printf("AList token fetched successfully, expires at: %v", AListTokenExpiry)
    return AListToken, nil
}

func saveSession(sessionID string, session *Session) error {
    data, err := json.Marshal(session)
    if err != nil {
        return err
    }
    return os.WriteFile(fmt.Sprintf("sessions/%s.json", sessionID), data, 0644)
}

func loadSession(sessionID string) (*Session, error) {
    data, err := os.ReadFile(fmt.Sprintf("sessions/%s.json", sessionID))
    if err != nil {
        return &Session{History: []APIMessage{}}, nil
    }
    var session Session
    if err := json.Unmarshal(data, &session); err != nil {
        return &Session{History: []APIMessage{}}, nil
    }
    return &session, nil
}

func cleanContent(content string) string {
    content = strings.ReplaceAll(content, "***", "")
    content = strings.TrimSpace(content)
    return content
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
    sessionID, err := r.Cookie("session_id")
    if err != nil {
        sessionID = &http.Cookie{
            Name:  "session_id",
            Value: fmt.Sprintf("%d", time.Now().UnixNano()),
            Path:  "/",
        }
        http.SetCookie(w, sessionID)
    }

    mu.Lock()
    if _, exists := sessions[sessionID.Value]; !exists {
        session, err := loadSession(sessionID.Value)
        if err != nil {
            log.Printf("Failed to load session: %v", err)
            session = &Session{History: []APIMessage{}}
        }
        sessions[sessionID.Value] = session
    }
    mu.Unlock()

    historyJSON, err := json.Marshal(sessions[sessionID.Value].History)
    if err != nil {
        log.Printf("Failed to marshal history: %v", err)
        historyJSON = []byte("[]")
    }

    data := struct {
        HistoryJSON template.JS
    }{HistoryJSON: template.JS(historyJSON)}

    tmplIndex.Execute(w, data)
}

func chatHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    sessionID, err := r.Cookie("session_id")
    if err != nil {
        log.Printf("Session not found: %v", err)
        http.Error(w, "Session not found", http.StatusBadRequest)
        return
    }

    var req ChatRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        log.Printf("Request decode error: %v", err)
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    // 支持 deepseek-v3 模型
    if req.Model != "deepseek-r1-distill-llama-70b" && req.Model != "deepseek-r1-distill-llama-8b" && req.Model != "deepseek-v3" {
        log.Printf("Unsupported model: %s", req.Model)
        http.Error(w, "Unsupported model", http.StatusBadRequest)
        return
    }

    mu.Lock()
    session := sessions[sessionID.Value]
    messages := append(session.History, APIMessage{Role: "user", Content: req.Message})
    session.History = messages
    mu.Unlock()

    // 根据模型设置参数
    temperature := float32(0.5)
    maxTokens := 2048
    if req.Model == "deepseek-v3" {
        temperature = 0.7  // deepseek-v3 默认温度
        maxTokens = 4096   // deepseek-v3 支持最大 4096 tokens
    }

    apiReq := APIRequest{
        Model:       req.Model,
        Messages:    messages,
        Stream:      true,
        Temperature: temperature,
        MaxTokens:   maxTokens,
    }
    reqBody, err := json.Marshal(apiReq)
    if err != nil {
        log.Printf("Failed to marshal API request: %v", err)
        fmt.Fprintf(w, "data: %s\n\n", `{"error": "Failed to marshal API request"}`)
        w.(http.Flusher).Flush()
        return
    }

    var resp *http.Response
    maxRetries := 3
    for attempt := 1; attempt <= maxRetries; attempt++ {
        startTime := time.Now()
        httpReq, err := http.NewRequest("POST", AliyunURL, bytes.NewBuffer(reqBody))
        if err != nil {
            log.Printf("Failed to create HTTP request: %v", err)
            fmt.Fprintf(w, "data: %s\n\n", `{"error": "Failed to create HTTP request"}`)
            w.(http.Flusher).Flush()
            return
        }
        httpReq.Header.Set("Authorization", "Bearer "+AliyunAPIKey)
        httpReq.Header.Set("Content-Type", "application/json")
        httpReq.Header.Set("Accept", "text/event-stream")

        resp, err = httpClient.Do(httpReq)
        if err == nil {
            log.Printf("API request succeeded on attempt %d for model %s: %v", attempt, req.Model, time.Since(startTime))
            break
        }
        log.Printf("API request failed on attempt %d: %v", attempt, err)
        if attempt == maxRetries {
            fmt.Fprintf(w, "data: %s\n\n", `{"error": "API request failed after `+fmt.Sprint(maxRetries)+` retries: `+err.Error()+`"}`)
            w.(http.Flusher).Flush()
            return
        }
        time.Sleep(time.Second * time.Duration(attempt))
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        log.Printf("API returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
        fmt.Fprintf(w, "data: %s\n\n", `{"error": "API returned non-200 status: `+resp.Status+`"}`)
        w.(http.Flusher).Flush()
        return
    }

    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")

    buf := make([]byte, 4096) // 增大缓冲区
    var reply string
    var totalTokens int
    maxStreamRetries := 2
    for attempt := 1; attempt <= maxStreamRetries+1; attempt++ {
        for {
            n, err := resp.Body.Read(buf)
            if err != nil {
                if err.Error() != "EOF" {
                    log.Printf("Stream read error on attempt %d: %v", attempt, err)
                    if attempt == maxStreamRetries+1 {
                        fmt.Fprintf(w, "data: %s\n\n", `{"error": "Stream read error after `+fmt.Sprint(maxStreamRetries)+` retries: `+err.Error()+`"}`)
                        w.(http.Flusher).Flush()
                        return
                    }
                    // 重试：重新发起请求
                    resp.Body.Close()
                    httpReq, _ := http.NewRequest("POST", AliyunURL, bytes.NewBuffer(reqBody))
                    httpReq.Header.Set("Authorization", "Bearer "+AliyunAPIKey)
                    httpReq.Header.Set("Content-Type", "application/json")
                    httpReq.Header.Set("Accept", "text/event-stream")
                    resp, err = httpClient.Do(httpReq)
                    if err != nil {
                        log.Printf("Failed to retry stream request: %v", err)
                        fmt.Fprintf(w, "data: %s\n\n", `{"error": "Failed to retry stream request: `+err.Error()+`"}`)
                        w.(http.Flusher).Flush()
                        return
                    }
                    break
                }
                // EOF 表示流结束
                break
            }
            data := string(buf[:n])
            log.Printf("Received stream chunk: %s", data)
            lines := bytes.Split([]byte(data), []byte("\n"))
            for _, line := range lines {
                if len(line) > 6 && string(line[:6]) == "data: " {
                    var streamResp StreamResponse
                    if err := json.Unmarshal(line[6:], &streamResp); err != nil {
                        log.Printf("Stream parse error: %v", err)
                        continue
                    }
                    if len(streamResp.Choices) > 0 {
                        content := cleanContent(streamResp.Choices[0].Delta.Content)
                        reply += content
                        data := map[string]interface{}{
                            "content":     content,
                            "model":       req.Model,
                            "totalTokens": totalTokens,
                        }
                        dataJSON, _ := json.Marshal(data)
                        fmt.Fprintf(w, "data: %s\n\n", dataJSON)
                        w.(http.Flusher).Flush()
                    }
                    if streamResp.Usage.TotalTokens > 0 {
                        totalTokens = streamResp.Usage.TotalTokens
                    }
                }
            }
        }
        // 如果没有错误，退出重试循环
        if err == nil || err.Error() == "EOF" {
            break
        }
    }

    mu.Lock()
    session.History = append(session.History, APIMessage{Role: "assistant", Content: reply})
    if err := saveSession(sessionID.Value, session); err != nil {
        log.Printf("Failed to save session: %v", err)
    }
    mu.Unlock()

    log.Printf("Response completed for model %s, total tokens: %d", req.Model, totalTokens)
}

func randomImageHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var req RandomImageRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        log.Printf("Random image request decode error: %v", err)
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    var imageURLs []map[string]interface{}
    apiKeys := make([]string, 0, len(RandomImageAPIs))
    for k := range RandomImageAPIs {
        apiKeys = append(apiKeys, k)
    }

    if req.IsTest {
        // 测试所有 API
        for _, api := range apiKeys {
            apiURL := RandomImageAPIs[api]
            resp, err := httpClient.Get(apiURL)
            status := "success"
            imageURL := ""
            if err != nil {
                log.Printf("Random image API %s failed: %v", api, err)
                status = "failed"
            } else {
                defer resp.Body.Close()
                imageURL = resp.Request.URL.String()
                if resp.StatusCode != http.StatusOK {
                    status = "failed"
                }
            }
            imageURLs = append(imageURLs, map[string]interface{}{
                "api":      api,
                "image_url": imageURL,
                "status":   status,
            })
        }
    } else {
        apiURL, exists := RandomImageAPIs[req.API]
        if !exists {
            log.Printf("Invalid API: %s", req.API)
            http.Error(w, "Invalid API", http.StatusBadRequest)
            return
        }
        resp, err := httpClient.Get(apiURL)
        if err != nil {
            log.Printf("Random image API request failed: %v", err)
            http.Error(w, "Failed to fetch random image", http.StatusInternalServerError)
            return
        }
        defer resp.Body.Close()
        imageURL := resp.Request.URL.String()
        imageURLs = append(imageURLs, map[string]interface{}{
            "api":      req.API,
            "image_url": imageURL,
            "status":   "success",
        })
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "images": imageURLs,
    })
}

func imageSearchHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var req ImageSearchRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        log.Printf("Image search request decode error: %v", err)
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    // 每页图片数量
    const imagesPerPage = 20
    page := req.Page
    if page < 1 {
        page = 1
    }
    startIndex := (page - 1) * imagesPerPage

    // 检查缓存
    cacheKey := fmt.Sprintf("%s:%s:%d", req.Query, req.Engine, page)
    imageCacheMu.RLock()
    if cachedImages, exists := imageCache[cacheKey]; exists {
        imageCacheMu.RUnlock()
        endIndex := startIndex + imagesPerPage
        if endIndex > len(cachedImages) {
            endIndex = len(cachedImages)
        }
        if startIndex > len(cachedImages) {
            startIndex = len(cachedImages)
        }
        paginatedImages := cachedImages[startIndex:endIndex]
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "images":     paginatedImages,
            "page":       page,
            "hasMore":    len(cachedImages) > endIndex,
            "totalFound": len(cachedImages),
        })
        return
    }
    imageCacheMu.RUnlock()

    // 清理过期缓存
    if time.Since(cacheLastClean) > 10*time.Minute {
        imageCacheMu.Lock()
        for key := range imageCache {
            delete(imageCache, key)
        }
        cacheLastClean = time.Now()
        imageCacheMu.Unlock()
    }

    // 选择 API
    var apiURL string
    switch req.Engine {
    case "baidu":
        apiURL = BaiduImageAPI
    case "sogou":
        apiURL = SogouImageAPI
    default:
        http.Error(w, "Invalid engine", http.StatusBadRequest)
        return
    }

    // 获取客户端 IP
    clientIP := r.RemoteAddr
    if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
        clientIP = strings.Split(forwardedFor, ",")[0]
    }

    // 从 API 获取图片
    imageURLs, err := fetchImagesFromAPI(apiURL, req.Query, page, req.Engine, clientIP)
    if err != nil {
        log.Printf("Failed to fetch images from %s: %v", req.Engine, err)
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "images":     []string{},
            "page":       page,
            "hasMore":    false,
            "totalFound": 0,
        })
        return
    }

    // 缓存结果
    imageCacheMu.Lock()
    imageCache[cacheKey] = imageURLs
    imageCacheMu.Unlock()

    // 按分页截取图片
    endIndex := startIndex + imagesPerPage
    if endIndex > len(imageURLs) {
        endIndex = len(imageURLs)
    }
    if startIndex > len(imageURLs) {
        startIndex = len(imageURLs)
    }
    paginatedImages := imageURLs[startIndex:endIndex]

    // 返回结果
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "images":     paginatedImages,
        "page":       page,
        "hasMore":    len(imageURLs) > endIndex,
        "totalFound": len(imageURLs),
    })
}

func fetchImagesFromAPI(apiURL, query string, page int, engine string, clientIP string) ([]string, error) {
    // 根据引擎选择对应的 ID 和 Key
    var apiID, apiKey string
    switch engine {
    case "baidu":
        apiID = BaiduImageAPIID
        apiKey = BaiduImageAPIKey
    case "sogou":
        apiID = SogouImageAPIID
        apiKey = SogouImageAPIKey
    default:
        return nil, fmt.Errorf("invalid engine: %s", engine)
    }

    // 构造 API 请求参数
    params := url.Values{}
    params.Add("id", apiID)
    params.Add("key", apiKey)
    params.Add("words", url.QueryEscape(query)) // 对中文关键词进行 URL 编码
    params.Add("page", fmt.Sprintf("%d", page))
    params.Add("limit", "20") // 每页 20 张图片
    params.Add("type", "1")   // 返回图片直链地址
    params.Add("uip", clientIP) // 使用动态获取的客户端 IP

    // 构造完整 URL
    fullURL := fmt.Sprintf("%s?%s", apiURL, params.Encode())

    // 发送 GET 请求
    req, err := http.NewRequest("GET", fullURL, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %v", err)
    }
    req.Header.Set("User-Agent", userAgents[time.Now().Nanosecond()%len(userAgents)])

    resp, err := httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to fetch images from %s: %v", engine, err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("API returned non-200 status: %d", resp.StatusCode)
    }

    // 解析 JSON 响应
    var apiResp ImageSearchAPIResponse
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read API response: %v", err)
    }

    if err := json.Unmarshal(body, &apiResp); err != nil {
        return nil, fmt.Errorf("failed to parse API response: %v", err)
    }

    if apiResp.Code != 200 {
        return nil, fmt.Errorf("API error: %s", apiResp.Msg)
    }

    // 过滤无效 URL
    var validURLs []string
    for _, url := range apiResp.Res {
        if strings.HasPrefix(url, "http") && !strings.Contains(url, "base64") {
            validURLs = append(validURLs, url)
        }
    }

    return validURLs, nil
}

func downloadImageHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var req struct {
        URL string `json:"url"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        log.Printf("Download image request decode error: %v", err)
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    resp, err := httpClient.Get(req.URL)
    if err != nil {
        log.Printf("Failed to download image: %v", err)
        http.Error(w, "Failed to download image", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    imageData, err := io.ReadAll(resp.Body)
    if err != nil {
        log.Printf("Failed to read image data: %v", err)
        http.Error(w, "Failed to read image data", http.StatusInternalServerError)
        return
    }

    token, err := fetchAListToken()
    if err != nil {
        log.Printf("Failed to get AList token: %v", err)
        http.Error(w, "Failed to get AList token", http.StatusInternalServerError)
        return
    }

    filename := fmt.Sprintf("image_%d.jpg", time.Now().UnixNano())
    filePath := AListUploadPath + "/" + filename

    uploadURL := AListURL + "/api/fs/put"
    httpReq, err := http.NewRequest("PUT", uploadURL, bytes.NewReader(imageData))
    if err != nil {
        log.Printf("Failed to create AList upload request: %v", err)
        http.Error(w, "Failed to create upload request", http.StatusInternalServerError)
        return
    }
    httpReq.Header.Set("Authorization", token)
    httpReq.Header.Set("File-Path", filePath)
    httpReq.Header.Set("Content-Type", "application/octet-stream")

    uploadResp, err := httpClient.Do(httpReq)
    if err != nil {
        log.Printf("Failed to upload to AList: %v", err)
        http.Error(w, "Failed to upload to AList", http.StatusInternalServerError)
        return
    }
    defer uploadResp.Body.Close()

    var alistResp AListUploadResponse
    if err := json.NewDecoder(uploadResp.Body).Decode(&alistResp); err != nil {
        log.Printf("Failed to parse AList response: %v", err)
        http.Error(w, "Failed to parse AList response", http.StatusInternalServerError)
        return
    }

    if alistResp.Code != 200 {
        log.Printf("AList upload failed: %s", alistResp.Msg)
        http.Error(w, "AList upload failed: "+alistResp.Msg, http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Image uploaded to AList successfully",
        "path":    filePath,
    })
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
    cookie, err := r.Cookie("admin_session")
    if err != nil || cookie.Value != "logged_in" {
        http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
        return
    }
    tmplAdmin.Execute(w, nil)
}

func handleAdminLogin(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        tmplAdminLogin.Execute(w, nil)
        return
    }

    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    if err := r.ParseForm(); err != nil {
        log.Printf("Error parsing form: %v", err)
        http.Error(w, "Failed to parse form", http.StatusBadRequest)
        return
    }

    username := r.FormValue("username")
    password := r.FormValue("password")
    log.Printf("Received login attempt: username=%s, password=%s", username, password)

    if username != adminUsername || password != adminPassword {
        log.Printf("Login failed: expected username=%s, password=%s", adminUsername, adminPassword)
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    log.Println("Login successful, setting cookie...")
    http.SetCookie(w, &http.Cookie{
        Name:  "admin_session",
        Value: "logged_in",
        Path:  "/",
    })
    http.Redirect(w, r, "/admin", http.StatusSeeOther)
    log.Println("Redirected to /admin")
}

func handleAdminLogout(w http.ResponseWriter, r *http.Request) {
    http.SetCookie(w, &http.Cookie{
        Name:   "admin_session",
        Value:  "",
        Path:   "/",
        MaxAge: -1,
    })
    http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func handleAddModel(w http.ResponseWriter, r *http.Request) {
    http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func handleRemoveModel(w http.ResponseWriter, r *http.Request) {
    http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func handleAddAPI(w http.ResponseWriter, r *http.Request) {
    http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func handleRemoveAPI(w http.ResponseWriter, r *http.Request) {
    http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func main() {
    if err := os.MkdirAll("sessions", 0755); err != nil {
        log.Fatalf("Failed to create sessions directory: %v", err)
    }

    go func() {
        for {
            _, err := fetchAListToken()
            if err != nil {
                log.Printf("Failed to fetch AList token: %v", err)
            }
            time.Sleep(24 * time.Hour)
        }
    }()

    log.Println("Step 2: Setting up routes...")
    http.HandleFunc("/", indexHandler)
    http.HandleFunc("/api/chat", chatHandler)
    http.HandleFunc("/api/random-image", randomImageHandler)
    http.HandleFunc("/api/search-image", imageSearchHandler)
    http.HandleFunc("/api/download-image", downloadImageHandler)
    http.HandleFunc("/admin", handleAdmin)
    http.HandleFunc("/admin/login", handleAdminLogin)
    http.HandleFunc("/admin/logout", handleAdminLogout)
    http.HandleFunc("/admin/add-model", handleAddModel)
    http.HandleFunc("/admin/remove-model", handleRemoveModel)
    http.HandleFunc("/admin/add-api", handleAddAPI)
    http.HandleFunc("/admin/remove-api", handleRemoveAPI)
    log.Println("Routes set up successfully")

    fmt.Println("Server starting on :4200...")
    log.Fatal(http.ListenAndServe(":4200", nil))
}