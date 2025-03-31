# ai
ai聊天源码

使用时先下载所有文件，需要更改主体文件中的密钥和alist的保存路径等

创建 templates/ 目录

 将 index.html 另存为 templates/index.html
 将 admin.html 另存为 templates/admin.html
 将 admin_login.html 另存为 templates/admin_login.html

下载后需要初始化并更新 Go 模块

最后编译运行即可

宝塔示例代码

cd ai_chat

go mod init ai_chat

go mod tidy

GOOS=linux GOARCH=amd64 go build -o ai_chat

cd /www/wwwroot/ai_chat

chmod +x ai_chat

nohup ./ai_chat > log.txt 2>&1 &

![1743182072891](https://github.com/user-attachments/assets/089fc2da-5d5b-47ef-8072-c7acc490b3ac)

![1743182157834](https://github.com/user-attachments/assets/62632317-f94b-49c3-9987-54f3c328c4c2)
