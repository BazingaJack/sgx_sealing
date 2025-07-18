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

func test_sys_prikey_cal(num int) error {
	// 开始计时
	startTime := time.Now()
	InfoLogger.Printf("Start %d times test", num)

	for i := 0; i < num; i++ {
		cmd := exec.Command("./app")
		
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
			ErrorLogger.Printf("failed to start ./app for iteration %d: %v", i, err)
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
			ErrorLogger.Printf("./app execution failed for iteration %d: %v", i, err)
			return err
		}

		// InfoLogger.Printf("Forge %d calculation successfully!", i)
	}

	// 计算总执行时间
	totalDuration := time.Since(startTime)
	InfoLogger.Printf("All %d tests passed successfully!", num)
	InfoLogger.Printf("Total duration: %v", totalDuration)
	InfoLogger.Printf("Average duration per test: %v", totalDuration/time.Duration(num))

	return nil
}

// func forge(s, t, r, t_new, q *big.Int) *big.Int {
// 	r_new1 := new(big.Int).Mul(s, r)
// 	r_new1.Add(r_new1, t)
// 	r_new1.Sub(r_new1, t_new)
// 	r_new2 := new(big.Int).ModInverse(s, q)
// 	r_new := new(big.Int).Mul(r_new1, r_new2)
// 	r_new.Mod(r_new, q)
// 	return r_new
// }

func main() {
	// 设置日志
	InfoLogger = log.New(os.Stdout, "[GO INFO]", log.Lshortfile)
	ErrorLogger = log.New(os.Stderr, "[GO ERROR]", log.Lshortfile)

	// s_hex := "22c0035b1ebdbccf1d14cc64b8c5cf2c8710ff31187957ba7641c520efda470"
	// r_hex := "d61b24ae313dc674406e40db56dacae3499dfe0e87b937dde05d0de58dc895a"
	// q_hex := "e8e14e68c1a6b6beff169bd76d2f79cc7051a8130c5f1fa019f229855d5184f"
	// s := new(big.Int)
	// s.SetString(s_hex, 16)
	// r := new(big.Int)
	// r.SetString(r_hex, 16)
	// q := new(big.Int)
	// q.SetString(q_hex, 16)

	// t := big.NewInt(123)
	// t_new := big.NewInt(456)
	// res := new(big.Int)

	// r_new := forge(s, t, r, t_new, q)
	if err := test_sys_prikey_cal(100); err != nil {
		ErrorLogger.Printf("Failed to calculate forge: %v", err)
	} else {
		InfoLogger.Printf("Calculate forge successfully!")
	}

	InfoLogger.Printf("Test passed successfully!")
	InfoLogger.Printf("All operations completed successfully!")
}
