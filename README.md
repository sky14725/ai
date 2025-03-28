# ai
ai聊天源码

使用时先下载所有文件，需要更改主体文件中的密钥和alist的保存路径等

下载后需要初始化并更新 Go 模块

最后编译运行即可

示例代码

cd ai_chat

go mod init ai_chat

go mod tidy

GOOS=linux GOARCH=amd64 go build -o ai_chat

cd /www/wwwroot/ai_chat

chmod +x ai_chat

nohup ./ai_chat > log.txt 2>&1 &

![1743182072891](https://github.com/user-attachments/assets/089fc2da-5d5b-47ef-8072-c7acc490b3ac)

