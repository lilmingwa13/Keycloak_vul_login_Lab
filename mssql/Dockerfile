# mssql/Dockerfile
FROM mcr.microsoft.com/mssql/server:2022-latest
USER root

###
RUN apt-get update && \
    apt-get install -y curl apt-transport-https gnupg && \
    # Thêm khóa GPG của Microsoft
    curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - && \
    # Thêm repo của Microsoft cho Ubuntu 22.04
    curl https://packages.microsoft.com/config/ubuntu/22.04/prod.list > /etc/apt/sources.list.d/mssql-release.list && \
    # Cập nhật lại danh sách gói và cài đặt mssql-tools
    apt-get update && \
    ACCEPT_EULA=Y apt-get install -y mssql-tools unixodbc-dev
###

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY init-db.sql /docker-entrypoint-initdb.d/init-db.sql
#add
#COPY entrypoint.sh /usr/local/bin/entrypoint.sh

# Cấp quyền thực thi cho script
RUN chmod +x /usr/local/bin/entrypoint.sh

USER mssql
# Ra lệnh cho container chạy script của chúng ta khi khởi động
CMD ["/usr/local/bin/entrypoint.sh"]