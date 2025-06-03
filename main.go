package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"bufio"
	"fmt"
)

var (
	InfoLogger *log.Logger
	ErrorLogger *log.Logger
)

type Config struct {
	BinaryPath      string `json:"binary_path"`
	DataFolder      string `json:"data_folder"`
	KeyFactorFolder string `json:"key_factor_folder"`
}

var config Config

func loadConfig() error {
	configFile, err := ioutil.ReadFile("config.json")
	if err != nil {
		ErrorLogger.Printf("failed to read config file: %v", err)
		return err
	}

	err = json.Unmarshal(configFile, &config)
	if err != nil {
		ErrorLogger.Printf("failed to parse config file: %v", err)
		return err
	}

	// 确保路径是绝对路径
	config.BinaryPath, err = filepath.Abs(config.BinaryPath)
	if err != nil {
		ErrorLogger.Printf("failed to get absolute path for binary: %v", err)
		return err
	}

	config.DataFolder, err = filepath.Abs(config.DataFolder)
	if err != nil {
		ErrorLogger.Printf("failed to get absolute path for data folder: %v", err)
		return err
	}

	config.KeyFactorFolder, err = filepath.Abs(config.KeyFactorFolder)
	if err != nil {
		ErrorLogger.Printf("failed to get absolute path for key factor folder: %v", err)
		return err
	}

	InfoLogger.Printf("Configuration loaded successfully:")
	InfoLogger.Printf("Binary Path: %s\n", config.BinaryPath)
	InfoLogger.Printf("Data Folder: %s\n", config.DataFolder)
	InfoLogger.Printf("Key Factor Folder: %s\n", config.KeyFactorFolder)

	return nil
}

func runCommand(command string, args ...string) error {
	cmd := exec.Command(config.BinaryPath, append([]string{command}, args...)...)

	// 创建管道捕获输出
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		ErrorLogger.Printf("failed to create stdout pipe: %v", err)
		return err
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		ErrorLogger.Printf("failed to create stderr pipe: %v", err)
		return err
	}

	// 启动命令
	if err := cmd.Start(); err != nil {
		ErrorLogger.Printf("failed to start command: %v", err)
		return err
	}

	// 读取输出
	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Println("[C++ INFO]", line)
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Println("[C++ ERROR]", line)
		}
	}()
	
	// 等待命令执行完成
	if err := cmd.Wait(); err != nil {
		ErrorLogger.Printf("command execution failed: %v", err)
		return err
	}
	
	return nil
}

func generateRSAKey(keyFactorPath ...string) error {
	var args []string
	if len(keyFactorPath) > 0 && keyFactorPath[0] != "" {
		targetPath := keyFactorPath[0]
		if err := os.MkdirAll(targetPath, 0755); err != nil {
			ErrorLogger.Printf("failed to create key factor directory: %v", err)
			return err
		}
		args = append(args, targetPath)
	}
	err := runCommand("generate_rsa_key", args...)
	return err
}

func encryptFile(params ...string) error {
    var args []string
    // 按顺序解析参数：inputFile, keyFactorPath, outputFile
    if len(params) > 0 && params[0] != "" {
        args = append(args, params[0]) // inputFile
    }
    if len(params) > 1 && params[1] != "" {
        args = append(args, params[1]) // keyFactorPath
    }
    if len(params) > 2 && params[2] != "" {
        args = append(args, params[2]) // outputFile
    }
    err := runCommand("encrypt", args...)
    return err
}

func decryptFile(params ...string) error {
    var args []string
    // 按顺序解析参数：inputFile, keyFactorPath, outputFile
    if len(params) > 0 && params[0] != "" {
        args = append(args, params[0]) // inputFile
    }
    if len(params) > 1 && params[1] != "" {
        args = append(args, params[1]) // keyFactorPath
    }
    if len(params) > 2 && params[2] != "" {
        args = append(args, params[2]) // outputFile
    }
    err := runCommand("decrypt", args...)
    return err
}


func ensureDirectories() error {
	// 确保数据目录存在
	if err := os.MkdirAll(config.DataFolder, 0755); err != nil {
		ErrorLogger.Printf("failed to create data directory: %v", err)
		return err
	}
	
	// 确保密钥因子目录存在
	if err := os.MkdirAll(config.KeyFactorFolder, 0755); err != nil {
		ErrorLogger.Printf("failed to create key factor directory: %v", err)
		return err
	}
	
	return nil
}

func main() {
	// 设置日志
	InfoLogger = log.New(os.Stdout, "[GO INFO]", log.Lshortfile)
	ErrorLogger = log.New(os.Stderr, "[GO ERROR]", log.Lshortfile)

	// 加载配置
	if err := loadConfig(); err != nil {
		ErrorLogger.Printf("Error loading config: %v", err)
	}
	
	// 确保目录存在
	if err := ensureDirectories(); err != nil {
		ErrorLogger.Printf("Error ensuring directories: %v", err)
	}
	
	// 示例使用
	InfoLogger.Printf("1. Generating RSA key...")
	if err := generateRSAKey(); err != nil {
		ErrorLogger.Printf("Failed to generate RSA key: %v", err)
	}
	InfoLogger.Printf("RSA key generated successfully!")
	
	// 假设我们有一个要加密的文件 input.txt
	inputFileName := "origin_data.txt"
	encryptedFileName := "encrypted_data.txt"
	
	InfoLogger.Printf("2. Encrypting file %s...\n", inputFileName)
	if err := encryptFile(); err != nil {
		ErrorLogger.Printf("Failed to encrypt file: %v", err)
	}
	InfoLogger.Printf("File encrypted successfully!")
	
	InfoLogger.Printf("3. Decrypting file %s...\n", encryptedFileName)
	if err := decryptFile(); err != nil {
		ErrorLogger.Printf("Failed to decrypt file: %v", err)
	}
	InfoLogger.Printf("File decrypted successfully!")
}
