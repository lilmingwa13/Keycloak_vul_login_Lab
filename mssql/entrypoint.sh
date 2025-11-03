#!/bin/bash

# Bắt đầu tiến trình SQL Server chạy nền
/opt/mssql/bin/sqlservr &

# Chờ 30 giây để đảm bảo server đã sẵn sàng nhận kết nối
echo "--- Waiting 30s for SQL Server to start..."
sleep 30s

# Chạy script khởi tạo database của chúng ta
echo "--- Running init-db.sql..."
/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P "Password@12345" -i /docker-entrypoint-initdb.d/init-db.sql

# Đưa tiến trình SQL Server lên chạy chính để giữ container không bị tắt
wait