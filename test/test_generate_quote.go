package main

import (
	"log"
	"os"
	"os/exec"
	"time"
	// "bufio"
	// "fmt"
)

var (
	InfoLogger *log.Logger
	ErrorLogger *log.Logger
)

func test_generate_quote(num int) error {
	// 开始计时
	startTime := time.Now()
	InfoLogger.Printf("Start %d times quote generation", num)

	for i := 0; i < num; i++ {
		// 直接运行 ./app_generate_quote 命令
		cmd := exec.Command("./app_generate_quote")
		
		// 设置工作目录为当前目录
		cmd.Dir = "."
		
		// // 创建管道捕获输出
		// stdoutPipe, err := cmd.StdoutPipe()
		// if err != nil {
		// 	ErrorLogger.Printf("failed to create stdout pipe for iteration %d: %v", i, err)
		// 	return err
		// }

		// stderrPipe, err := cmd.StderrPipe()
		// if err != nil {
		// 	ErrorLogger.Printf("failed to create stderr pipe for iteration %d: %v", i, err)
		// 	return err
		// }

		// 启动命令
		if err := cmd.Start(); err != nil {
			ErrorLogger.Printf("failed to start ./app_generate_quote for iteration %d: %v", i, err)
			return err
		}

		// // 读取输出
		// go func() {
		// 	scanner := bufio.NewScanner(stdoutPipe)
		// 	for scanner.Scan() {
		// 		line := scanner.Text()
		// 		fmt.Printf("[C++ INFO %d] %s\n", i, line)
		// 	}
		// }()

		// go func() {
		// 	scanner := bufio.NewScanner(stderrPipe)
		// 	for scanner.Scan() {
		// 		line := scanner.Text()
		// 		fmt.Printf("[C++ ERROR %d] %s\n", i, line)
		// 	}
		// }()
		
		// 等待命令执行完成
		if err := cmd.Wait(); err != nil {
			ErrorLogger.Printf("./app_generate_quote execution failed for iteration %d: %v", i, err)
			return err
		}
		
		// InfoLogger.Printf("Quote %d generated successfully!", i)
	}

	// 计算总执行时间
	totalDuration := time.Since(startTime)
	InfoLogger.Printf("All %d quotes generated successfully!", num)
	InfoLogger.Printf("Total duration: %v", totalDuration)
	InfoLogger.Printf("Average duration per quote: %v", totalDuration/time.Duration(num))

	return nil
}

func main() {
	// 设置日志
	InfoLogger = log.New(os.Stdout, "[GO INFO]", log.Lshortfile)
	ErrorLogger = log.New(os.Stderr, "[GO ERROR]", log.Lshortfile)
	
	// 示例使用
	if err := test_generate_quote(10); err != nil {
		ErrorLogger.Printf("Failed to generate quote: %v", err)
	}
	InfoLogger.Printf("Quote generated successfully!")

	InfoLogger.Printf("All operations completed successfully!")
}
