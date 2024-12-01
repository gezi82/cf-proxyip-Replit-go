package main

import (
    "bufio"
    "crypto/tls"
    "fmt"
    "net"
    "os"
    "strings"
    "sync"
    "time"
)

func main() {
    // 打开 ip.txt 文件
    file, err := os.Open("ip.txt")
    if err != nil {
        fmt.Println("无法打开文件:", err)
        return
    }
    defer file.Close()

    // 创建一个文件用于写入合格的 IP 地址
    outFile, err := os.OpenFile("443.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        fmt.Println("无法创建文件:", err)
        return
    }
    defer outFile.Close()

    // 创建一个 bufio.Scanner 用于逐行读取文件内容
    scanner := bufio.NewScanner(file)
    tasks := make(chan string, 5) // 并发任务通道
    results := make(chan string)  // 结果通道
    var wg sync.WaitGroup         // 等待所有任务完成

    // 开启并发任务处理
    for i := 0; i < 5; i++ {
        wg.Add(1)
        go handleTask(tasks, results, &wg)
    }

    // 逐行读取文件内容并发送到并发任务通道
    for scanner.Scan() {
        ip := scanner.Text()
        tasks <- ip
    }

    // 关闭并发任务通道，等待所有任务完成
    close(tasks)
    go func() {
        wg.Wait()
        close(results)
    }()

    // 从结果通道中读取合格的 IP 地址并写入到文件中
    for ip := range results {
        outFile.WriteString(ip + "n")
    }

    if err := scanner.Err(); err != nil {
        fmt.Println("读取文件时发生错误:", err)
        return
    }

    fmt.Println("处理完毕，合格的 IP 已追加到 443.txt 文件中")
}

// 函数用于处理并发任务
func handleTask(tasks <-chan string, results chan<- string, wg *sync.WaitGroup) {
    defer wg.Done()
    for ip := range tasks {
        // 检查 IP 的 443 端口是否可访问，超时设置为 5 秒
        if isPortOpenWithTimeout(ip, "443", 5*time.Second) {
            // 如果 443 端口可访问，继续检查证书是否来自 cloudflare-dns.com
            if checkCertificate(ip, "cloudflare-dns.com") {
                // 如果证书来自 cloudflare-dns.com，写入到结果通道中
                fmt.Println(ip, "合格")
                results <- ip
            } else {
                fmt.Println(ip, "不合格，证书不是来自 cloudflare-dns.com")
            }
        } else {
            fmt.Println(ip, "不合格，443端口不可访问或超时")
        }
    }
}

// 函数用于检查指定 IP 和端口是否可访问，并设置超时时间
func isPortOpenWithTimeout(ip, port string, timeout time.Duration) bool {
    conn, err := net.DialTimeout("tcp", ip+":"+port, timeout)
    if err != nil {
        return false
    }
    defer conn.Close()
    return true
}

// 函数用于检查指定 IP 的证书是否来自指定的域名
func checkCertificate(ip, domain string) bool {
    config := tls.Config{ServerName: domain}
    conn, err := tls.Dial("tcp", ip+":443", &config)
    if err != nil {
        return false
    }
    defer conn.Close()

    // 获取证书
    certs := conn.ConnectionState().PeerCertificates
    if len(certs) < 1 {
        return false
    }

    // 检查证书是否匹配指定的域名
    for _, cert := range certs {
        if strings.Contains(cert.Subject.CommonName, domain) || cert.VerifyHostname(domain) == nil {
            return true
        }
    }
    return false
}